use crate::client::{probe_frame, rejects_probe, Credentials};
use crate::objects::{AccountKey, AdvKey, ProbeChallenge, ProbeChallengeResponse};
use crate::{Command, Frame, WppObject};

pub const SECRET_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    SecretLength { given: usize },
    SecretNotAscii,
    AccountIdZero,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingState {
    Idle,
    Probing,
    Associating { mac: String },
    FinishingSetup { mac: String },
    Readopting(Credentials),
    Paired(Credentials),
    AlreadyAssociated,
}

#[derive(Debug)]
pub struct Pairing {
    secret: String,
    account_id: u32,
    known: Vec<Credentials>,
    state: PairingState,
}

impl Pairing {
    pub fn new(
        secret: String,
        account_id: u32,
        known: Vec<Credentials>,
    ) -> Result<Pairing, PairingError> {
        if secret.len() != SECRET_LEN {
            return Err(PairingError::SecretLength {
                given: secret.len(),
            });
        }
        if !secret.is_ascii() {
            return Err(PairingError::SecretNotAscii);
        }
        if account_id == 0 {
            return Err(PairingError::AccountIdZero);
        }
        Ok(Pairing {
            secret,
            account_id,
            known: known
                .into_iter()
                .map(|c| Credentials {
                    mac: c.mac.to_ascii_lowercase(),
                    secret: c.secret,
                })
                .collect(),
            state: PairingState::Idle,
        })
    }

    pub fn state(&self) -> &PairingState {
        &self.state
    }

    pub fn on_connected(&mut self) -> Vec<Frame> {
        self.state = PairingState::Probing;
        vec![probe_frame()]
    }

    pub fn on_disconnected(&mut self) {
        if !matches!(self.state, PairingState::Paired(_)) {
            self.state = PairingState::Idle;
        }
    }

    pub fn on_frame(&mut self, frame: &Frame) -> Vec<Frame> {
        let opcode = frame.command.opcode();
        if opcode == Command::CMD_ERROR.0 && rejects_probe(frame) {
            self.state = PairingState::AlreadyAssociated;
            return Vec::new();
        }

        match &self.state {
            PairingState::Probing if opcode == Command::CMD_PROBE_CHALLENGE.0 => {
                let Some(challenge) = frame.objects.iter().find_map(|o| match o {
                    WppObject::ProbeChallenge(c) => Some(c.clone()),
                    _ => None,
                }) else {
                    return Vec::new();
                };
                let identity = challenge.mac.to_ascii_lowercase();
                let Some(credentials) = self.known.iter().find(|c| c.mac == identity).cloned()
                else {
                    self.state = PairingState::AlreadyAssociated;
                    return Vec::new();
                };
                let answer = credentials.answer(&challenge.challenge);
                self.state = PairingState::Readopting(credentials);
                vec![Frame::new(
                    Command::CMD_PROBE_CHALLENGE,
                    vec![
                        WppObject::ProbeChallengeResponse(ProbeChallengeResponse { answer }),
                        WppObject::ProbeChallenge(ProbeChallenge {
                            mac: identity,
                            challenge: vec![0; 16],
                        }),
                    ],
                )]
            }
            PairingState::Readopting(credentials) if opcode == Command::CMD_PROBE.0 => {
                self.state = PairingState::Paired(credentials.clone());
                Vec::new()
            }
            PairingState::Probing if opcode == Command::CMD_PROBE.0 => {
                let Some(reply) = frame.objects.iter().find_map(|o| match o {
                    WppObject::ProbeReply(r) => Some(r.clone()),
                    _ => None,
                }) else {
                    return Vec::new();
                };
                self.state = PairingState::Associating { mac: reply.mac };
                vec![Frame::new(
                    Command::CMD_ASSOCIATION_KEYS_SET,
                    vec![
                        WppObject::AccountKey(AccountKey {
                            id: self.account_id,
                            secret: self.secret.clone(),
                        }),
                        WppObject::AdvKey(AdvKey {
                            secret: self.secret.clone(),
                        }),
                    ],
                )]
            }
            PairingState::Associating { mac } if opcode == Command::CMD_ASSOCIATION_KEYS_SET.0 => {
                self.state = PairingState::FinishingSetup { mac: mac.clone() };
                vec![Frame::new(Command::CMD_SETUP_OK, Vec::new())]
            }
            PairingState::FinishingSetup { mac } if opcode == Command::CMD_SETUP_OK.0 => {
                self.state = PairingState::Paired(Credentials {
                    mac: mac.clone(),
                    secret: self.secret.clone(),
                });
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::{Cmderror, ProbeChallenge, ProbeReply};

    const SECRET: &str = "gUf8Np69A4GvJxjY1XOcIHKQm2HcPZnO";
    const MAC: &str = "a4:7e:fa:44:d6:10";

    fn pairing() -> Pairing {
        Pairing::new(SECRET.to_string(), 19071510, Vec::new()).unwrap()
    }

    fn knowing_the_watch() -> Pairing {
        Pairing::new(
            "a different key, of the very same length".to_string()[..SECRET_LEN].to_string(),
            19071510,
            vec![Credentials {
                mac: MAC.to_ascii_uppercase(),
                secret: SECRET.to_string(),
            }],
        )
        .unwrap()
    }

    fn challenge() -> Frame {
        Frame::new(
            Command::CMD_PROBE_CHALLENGE,
            vec![WppObject::ProbeChallenge(ProbeChallenge {
                mac: MAC.to_string(),
                challenge: vec![
                    244, 197, 79, 127, 24, 111, 82, 130, 216, 87, 5, 54, 35, 63, 193, 35,
                ],
            })],
        )
    }

    fn probe_reply() -> Frame {
        Frame::new(
            Command::CMD_PROBE,
            vec![WppObject::ProbeReply(ProbeReply {
                vid: 0,
                pid: 0,
                name: "ScanWatch 2".to_string(),
                mac: MAC.to_string(),
                secret: String::new(),
                hard_version: 16777215,
                mfg_id: "00280074".to_string(),
                bl_version: 8,
                soft_version: 3411,
                rescue_version: 16777215,
            })],
        )
    }

    #[test]
    fn a_secret_of_the_wrong_length_is_refused() {
        assert_eq!(
            Pairing::new("short".to_string(), 1, Vec::new()).err(),
            Some(PairingError::SecretLength { given: 5 })
        );
    }

    #[test]
    fn a_free_watch_is_sent_the_keys_and_identifies_itself() {
        let mut pairing = pairing();
        let opening = pairing.on_connected();
        assert_eq!(opening[0].command, Command::CMD_PROBE);

        let sent = pairing.on_frame(&probe_reply());
        assert_eq!(sent[0].command, Command::CMD_ASSOCIATION_KEYS_SET);
        assert_eq!(
            sent[0].objects,
            vec![
                WppObject::AccountKey(AccountKey {
                    id: 19071510,
                    secret: SECRET.to_string(),
                }),
                WppObject::AdvKey(AdvKey {
                    secret: SECRET.to_string(),
                }),
            ]
        );

        let sent = pairing.on_frame(&Frame::new(Command::CMD_ASSOCIATION_KEYS_SET, Vec::new()));
        assert_eq!(sent[0].command, Command::CMD_SETUP_OK);
        assert!(!matches!(pairing.state(), PairingState::Paired(_)));

        pairing.on_frame(&Frame::new(Command::CMD_SETUP_OK, Vec::new()));
        assert_eq!(
            pairing.state(),
            &PairingState::Paired(Credentials {
                mac: MAC.to_string(),
                secret: SECRET.to_string(),
            })
        );
    }

    #[test]
    fn a_watch_that_challenges_with_an_unknown_identity_is_someone_elses() {
        let mut pairing = pairing();
        pairing.on_connected();
        let sent = pairing.on_frame(&challenge());
        assert!(sent.is_empty());
        assert_eq!(pairing.state(), &PairingState::AlreadyAssociated);
    }

    #[test]
    fn a_watch_we_already_have_a_key_for_is_answered_and_taken_back() {
        let mut pairing = knowing_the_watch();
        pairing.on_connected();
        let sent = pairing.on_frame(&challenge());
        assert_eq!(sent[0].command, Command::CMD_PROBE_CHALLENGE);
        assert!(sent[0].objects.contains(&WppObject::ProbeChallengeResponse(
            ProbeChallengeResponse {
                answer: vec![
                    84, 20, 165, 52, 232, 6, 253, 184, 77, 32, 105, 86, 199, 96, 220, 232, 42, 76,
                    25, 32
                ],
            }
        )));

        pairing.on_frame(&Frame::new(Command::CMD_PROBE, Vec::new()));
        assert_eq!(
            pairing.state(),
            &PairingState::Paired(Credentials {
                mac: MAC.to_string(),
                secret: SECRET.to_string(),
            })
        );
    }

    #[test]
    fn a_key_the_watch_no_longer_holds_ends_the_attempt() {
        let mut pairing = knowing_the_watch();
        pairing.on_connected();
        pairing.on_frame(&challenge());
        pairing.on_frame(&Frame::new(
            Command::CMD_ERROR,
            vec![WppObject::Cmderror(Cmderror {
                cmd: Command::CMD_PROBE_CHALLENGE.0,
                err: -5,
            })],
        ));
        assert_eq!(pairing.state(), &PairingState::AlreadyAssociated);
    }

    #[test]
    fn a_refused_probe_is_the_same_answer() {
        let mut pairing = pairing();
        pairing.on_connected();
        pairing.on_frame(&Frame::new(
            Command::CMD_ERROR,
            vec![WppObject::Cmderror(Cmderror {
                cmd: Command::CMD_PROBE.0,
                err: -5,
            })],
        ));
        assert_eq!(pairing.state(), &PairingState::AlreadyAssociated);
    }

    #[test]
    fn chatter_before_the_reply_is_ignored() {
        let mut pairing = pairing();
        pairing.on_connected();
        let sent = pairing.on_frame(&Frame::new(
            Command::CMD_SYNC_REQUEST.with_channel(crate::Channel::SlaveRequest),
            Vec::new(),
        ));
        assert!(sent.is_empty());
        assert_eq!(pairing.state(), &PairingState::Probing);
    }

    #[test]
    fn a_link_lost_before_the_keys_land_starts_over() {
        let mut pairing = pairing();
        pairing.on_connected();
        pairing.on_frame(&probe_reply());
        pairing.on_disconnected();
        assert_eq!(pairing.state(), &PairingState::Idle);
        assert_eq!(pairing.on_connected()[0].command, Command::CMD_PROBE);
    }
}
