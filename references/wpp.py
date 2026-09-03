from abc import ABC, abstractmethod
from datetime import date, datetime
from enum import Enum, IntEnum, IntFlag, unique
import hashlib
import struct
import typing
from typing import (
    Annotated,
    ClassVar,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
    get_args,
    get_origin,
)
from inspect import get_annotations

from annotated_types import Len, Interval
from pydantic import BaseModel, Strict
from pydantic_extra_types.mac_address import MacAddress


@unique
class Cmd(Enum):
    CMD_ADC = 523
    CMD_ALARM_GET = 290
    CMD_ALARM_SET = 283
    CMD_ALGO_PARAM_SET = 2474
    CMD_AMAZON_AUTH_CODE = 2394
    CMD_AMAZON_CODE_CHALLENGE_REQUEST = 2396
    CMD_ANS_GET = 2372
    CMD_ANS_SET = 2373
    CMD_APP_CAPABILITIES = 2445
    CMD_APP_IS_ALIVE = 2412
    CMD_AS6221_MEASURE = 2473
    CMD_ASSOCIATION_KEYS_SET = 308
    CMD_AUDIOTEST = 520
    CMD_BACKLIGHT = 514
    CMD_BATTERY_PERCENT = 261
    CMD_BATTERY_STATUS = 1284
    CMD_BLE_SHELL = 2413
    CMD_BLE_SHELL_CHALLENGE = 2414
    CMD_BODY_VASISTAS_GET = 2344
    CMD_BOOTSTRAP_REBOOT = 2444
    CMD_BOOTSTRAP_REDIRECT = 2443
    CMD_BOOT_COUNT_GET = 2384
    CMD_BREATHE_CONFIG_SET = 2456
    CMD_CACHE_INVALIDATE = 2410
    CMD_CALIBRATION_GET = 2350
    CMD_CALIBRATION_SET = 2349
    CMD_CAPTURE_MODE_START = 304
    # CMD_CHANNEL_MASK = 0x4000
    CMD_CHANNEL_MASTER_REQUEST = 0
    CMD_CHANNEL_NOTIF = 0x8000
    CMD_CHANNEL_SLAVE_REQUEST = 16384
    CMD_CLASSIFICATION_REGION_GET = 333
    CMD_CLASSIFICATION_REGION_SET = 334
    CMD_CLEANSING_MODE = 2485
    CMD_CLOSE = 303
    CMD_COMM_SUPPORT = 281
    CMD_CONNECT_REASON = 273
    CMD_COVID_INFO_GET = 2437
    CMD_COVID_INFO_SET = 2436
    CMD_COVID_REPORT_GET = 2438
    CMD_CUSTOMIZATION_ID = 2368
    CMD_CUSTO_SCREEN_SET = 338
    CMD_CYCLE_TRACKING_GET_MANUAL_LOG_START_OF_MENSTRUATION = 2492
    CMD_CYCLE_TRACKING_SET_CYCLES = 2489
    CMD_DAC = 522
    CMD_DBLIB_DUMP = 278
    CMD_DEBUG_DUMP = 280
    CMD_DEBUG_DUMP_ACK = 309
    CMD_DEBUG_SET = 279
    CMD_DEMO_START = 285
    CMD_DEMO_STOP = 288
    CMD_DEVICE_CHALLENGE = 2482
    CMD_DIGITAL_CROWN_CALIB = 2433
    CMD_DISCONNECT = 272
    CMD_DISCONNECT_AND_FAST_ADV = 2323
    CMD_DISPLAYED_DELTA_GET = 2399
    CMD_DISPLAYED_DELTA_SET = 2401
    CMD_DISPLAYED_INFO_GET = 2464
    CMD_DISPLAY_PREFS_GET = 2340
    CMD_DISPLAY_PREFS_SET = 2341
    CMD_DUMP = 528
    CMD_ECG_DETECTION_TEST = 2426
    CMD_ECG_TEST = 2425
    CMD_ERROR = 256
    CMD_ETH_CONNECT = 266
    CMD_ETH_SETTINGS = 268
    CMD_EVENTS_DEL = 2452
    CMD_EVENTS_GET_V2 = 2451
    CMD_FACTORY_BATTERY_STATE = 2428
    CMD_FACTORY_MODE_GET = 2415
    CMD_FACTORY_MODE_SET = 2416
    CMD_FACTORY_PROBE = 310
    CMD_FACTORY_RESET = 291
    CMD_FACTORY_TEST = 2483
    CMD_FACTORY_TEST_GET = 2484
    CMD_FEATURE_MASK_GET = 305
    CMD_FEATURE_MASK_SET = 306
    CMD_FEATURE_TAGS_SET = 2439
    CMD_FEATURE_TAGS_SET_DEPRECATED = 2435
    CMD_FLUX_SENSOR_MEASURE = 2480
    CMD_FRICTION_LONG_TEST = 2397
    CMD_FRICTION_TEST = 2337
    CMD_FW_AVAILABLE = 2407
    CMD_GATEWAY_MAC_GET = 2455
    CMD_GET_ALARM = 293
    CMD_GET_ALARM_DELAY = 2332
    CMD_GET_ALARM_ENABLED = 2330
    CMD_GET_ALARM_SETTINGS = 298
    CMD_GET_CARTRIDGE_INFO_FROM_DEVICE = 2466
    CMD_GET_HOME_SCREEN = 2354
    CMD_GET_HR = 2343
    CMD_GET_LAMP_STATUS = 2318
    CMD_GET_LIGHT_SENSOR = 2352
    CMD_GET_LIVE_HR = 2376
    CMD_GET_LUMINOSITY_LEVEL = 2370
    CMD_GET_MULTI_ALARM = 326
    CMD_GET_PRESSURE_TEMPERATURE = 329
    CMD_GET_RESPONSIVE_LIGHT = 2328
    CMD_GET_RT_ENV_MEASURE = 2339
    CMD_GET_SPORT_MODE = 2371
    CMD_GET_SYMPTOMS = 2488
    CMD_GET_TRACKER_WEAR_POS = 336
    CMD_GET_UDI = 2429
    CMD_GET_WSD_SETTINGS = 2320
    CMD_GLANCE_GET = 2427
    CMD_GLANCE_SET = 2417
    CMD_GLYPH_GET = 2403
    CMD_GPIO = 516
    CMD_GREENTEG_SENSITIVITY_BIN_GET = 2491
    CMD_GREENTEG_SENSITIVITY_BIN_SET = 2486
    CMD_HANDS_CAL_CANCEL = 2422
    CMD_HANDS_CAL_START = 286
    CMD_HANDS_CAL_STOP = 287
    CMD_HANDS_MOVE = 284
    CMD_HAND_UNBLOCK_TRACKER = 2418
    CMD_HR_AUTO_ALGORITHM_GET = 313
    CMD_HR_AUTO_ALGORITHM_SET = 312
    CMD_HR_MEASURE = 2434
    CMD_HWA03_RH_GET = 314
    CMD_IAP_RWCI = 530
    CMD_IFSTATE = 267
    CMD_INACTIVITY_CFG_GET = 2458
    CMD_INACTIVITY_CFG_SET = 2457
    CMD_INSTALL_MODE_GET = 2461
    CMD_INSTALL_MODE_SET = 2462
    CMD_LCD = 515
    CMD_LOCALE_GET = 324
    CMD_LOCALE_SET = 282
    CMD_LOCAL_EVENT_NOTIFY = 2459
    CMD_LOCAL_NOTIFICATIONS_CONFIG_GET = 2449
    CMD_LOCAL_NOTIFICATIONS_CONFIG_SET = 2448
    CMD_MAX8614X_FACTORY_STATS_START = 2431
    CMD_MAX8614X_FACTORY_STATS_STOP = 2432
    CMD_MAX8617X_FACTORY_STATS_START = 2470
    CMD_MAX8617X_FACTORY_STATS_STOP = 2471
    CMD_MCP3422_MEASURE = 2472
    CMD_MCU_TEMP_CAL_GET = 2348
    CMD_MCU_TEMP_CAL_SET = 2347
    CMD_MEASURE_LIVE_DATA = 2421
    CMD_MEASURE_START = 2419
    CMD_MEASURE_STOP = 2420
    CMD_MTU_EXCH = 341
    CMD_NETUPDATE_REBOOT = 1041
    CMD_NETUPDATE_START = 1040
    CMD_NO2_CAL = 2395
    CMD_NOTIFICATION_APP_ENABLED_GET = 2405
    CMD_NOTIFICATION_APP_ENABLED_SET = 2406
    CMD_NOTIFICATION_GET = 2404
    CMD_NOTIFY_MEASURE_PROCESS_STEP = 332
    CMD_PERSO = 517
    CMD_PLS_GET = 299
    CMD_PLS_LIST = 302
    CMD_PLS_RM = 301
    CMD_PLS_SET = 300
    CMD_PROBE = 257
    CMD_PROBESCAN = 262
    CMD_PROBE_CHALLENGE = 296
    CMD_RAW_DATA = 343
    CMD_RAW_DATA_STREAM_CONTROL = 2400
    CMD_REBOOT = 337
    CMD_REMOTE_NOTIFICATIONS_CONFIG_GET = 2353
    CMD_REMOTE_NOTIFICATIONS_CONFIG_SET = 2345
    CMD_REQUEST_FW_CHUNK = 2408
    CMD_REQUEST_FW_CHUNK_CRC = 2409
    CMD_RESTART_TO_UPDATE = 294
    CMD_RTC = 527
    CMD_RUN_PARAMETERS_SET = 2336
    CMD_SCALE_MEDAPP_USER_INFO = 307
    CMD_SCALE_SESSION = 269
    CMD_SCREEN_LIST_SET = 1292
    CMD_SCREEN_SETTINGS_GET = 1293
    CMD_SCREEN_STATE_SET = 2398
    CMD_SELFTEST = 529
    CMD_SEND_CARTRIDGE_INFO_TO_APP = 2467
    CMD_SEND_ENV_MEASURE = 2338
    CMD_SENSOR_ID_SET = 311
    CMD_SETUP_OK = 275
    CMD_SET_ALARM = 292
    CMD_SET_ALARM_ENABLED = 2331
    CMD_SET_BLE_LINK_STATUS = 2322
    CMD_SET_CLOCK_MODE = 2314
    CMD_SET_HOME_SCREEN = 2351
    CMD_SET_LAMP_STATUS = 2317
    CMD_SET_LUMINOSITY_LEVEL = 2369
    CMD_SET_MULTI_ALARM = 325
    CMD_SET_REMOTE_ID = 2375
    CMD_SET_RESPONSIVE_LIGHT = 2327
    CMD_SET_SYMPTOMS = 2487
    CMD_SET_TAPPING = 2333
    CMD_SET_TIME = 289
    CMD_SET_TRACKER_WEAR_POS = 335
    CMD_SET_WSD_SETTINGS = 2319
    CMD_SHORTCUT_GET = 2450
    CMD_SHORTCUT_SET = 2441
    CMD_SIGNAL_GET = 2393
    CMD_SKIN_TEMPERATURE_MEASURE = 2481
    CMD_SLEEP_ACTIVITY_GET = 2391
    CMD_SN19020X6_MEASURE = 2479
    CMD_SPIFLASH = 526
    CMD_SPI_FLASH = 2386
    CMD_SPOTIFY_PRESET = 2329
    CMD_STANDBY = 518
    CMD_START_INSTALL_CARTRIDGE = 2468
    CMD_STOP_INSTALL_CARTRIDGE = 2469
    CMD_STORED_MEASURE = 271
    CMD_STORED_MEASURE_SIGNAL_DEL = 328
    CMD_STORED_MEASURE_SIGNAL_GET = 327
    CMD_STRIP_COUNT_GET = 2463
    CMD_STRIP_MEAS_START = 2460
    CMD_SWAP_VASISTAS_GET = 2402
    CMD_SWIM_PARAMETERS_SET = 2326
    CMD_SWIM_STATUS_SET = 2334
    CMD_SYNC_OK = 277
    CMD_SYNC_REQUEST = 321
    CMD_TEST_MODE_TIME = 295
    CMD_TEST_SCREEN_SET = 2411
    CMD_THRESHOLDS_GET = 2447
    CMD_THRESHOLDS_SET = 2446
    CMD_TIME_COUNTERS_GET = 2385
    CMD_TIME_GET = 1291
    CMD_TIME_SET = 1281
    CMD_TLS_CLOSE = 2465
    CMD_TMP117_MEASURE = 2478
    CMD_TRACE = 263
    CMD_TRACKER_GOAL_SET = 1290
    CMD_TRACKER_MOVE_HANDS_GET = 2476
    CMD_TRACKER_MOVE_HANDS_SET = 2475
    CMD_TRACKER_USER_GET = 1283
    CMD_TRACKER_USER_SET = 1282
    CMD_TRUSTED_CONTACTS_ALERT = 2387
    CMD_UNKNOWN_DATA_GET = 2377
    CMD_UPDATE_ALARM = 297
    CMD_UPDATE_USER_INFO = 276
    CMD_UP_FIRMWARE_ACK = 1026
    CMD_UP_FIRMWARE_REBOOT = 1027
    CMD_UP_FIRMWARE_START = 1025
    CMD_USER_ACTION = 2374
    CMD_USER_UNIT = 274
    CMD_VASISTAS_GET = 2424
    CMD_VASISTAS_GET_BACKGROUND = 2324
    CMD_VIBRATOR = 2490
    CMD_VIBRATOR_PATTERN_GET = 2388
    CMD_VIBRATOR_PATTERN_GET_PATTERNS = 2390
    CMD_VIBRATOR_PATTERN_SET = 2389
    CMD_WALK_PARAMETERS_SET = 2335
    CMD_WAM_AUTO_SLEEP = 1289
    CMD_WAM_AUTO_SLEEP_GET = 2342
    CMD_WAM_DISPLAYED_INFO_GET = 1285
    CMD_WAM_RAW_DATA_GET = 1287
    CMD_WAM_SCREENS_LIST = 1288
    CMD_WAM_SCREENS_LIST_GET = 2423
    CMD_WAM_VASISTAS_GET = 1286
    CMD_WEIGHTTEST = 521
    CMD_WIFI_ANT = 513
    CMD_WIFI_CONNECT = 259
    CMD_WIFI_COUNTRY = 264
    CMD_WIFI_GET_SETTINGS = 260
    CMD_WIFI_SCAN = 258
    CMD_WIFI_SCAN_LCD = 519
    CMD_WIFI_SETTINGS = 265
    CMD_WL = 524
    CMD_WORKOUT_ALWAYS_ON_GET = 2454
    CMD_WORKOUT_ALWAYS_ON_SET = 2453
    CMD_WORKOUT_FACE_MODE = 319
    CMD_WORKOUT_GPS_STATUS = 323
    CMD_WORKOUT_LIVE_DATA = 320
    CMD_WORKOUT_SCREEN_LIST_GET = 315
    CMD_WORKOUT_SCREEN_SET = 316
    CMD_WORKOUT_SETTINGS_GET = 2477
    CMD_WORKOUT_SET_STATE = 2430
    CMD_WORKOUT_START = 317
    CMD_WORKOUT_STATUS = 322
    CMD_WORKOUT_STOP = 318
    CMD_WPM_FACTORY_GETPRESSURE = 1913
    CMD_WPM_FACTORY_GETZERO = 1917
    CMD_WPM_FACTORY_SETMOTOR = 1912
    CMD_WPM_FACTORY_SETVALVE = 1911
    CMD_WPM_KEEPALIVE = 1890
    CMD_WPM_MODE = 1888
    CMD_WPM_PARAMETER_GET = 330
    CMD_WPM_PARAMETER_SET = 331
    CMD_WPM_START = 1889
    CMD_WPM_STOP = 1891
    CMD_WPM_STS_BP_EVENT = 1894
    CMD_WPM_STS_BP_PULSE = 1893
    CMD_WPM_STS_BP_RESULT = 1892
    CMD_WPM_STS_PRESSURE = 1923
    CMD_WPP_CAPABILITIES = 2325
    CMD_WSD_GET_PROGRAM_LIST = 2313
    CMD_WSD_GET_PROGRAM_SETTINGS = 2310
    CMD_WSD_GET_STATUS = 2311
    CMD_WSD_LED_CONTROL_WSM = 2316
    CMD_WSD_PAUSE_PROGRAM = 2321
    CMD_WSD_SCAN_WSM = 2305
    CMD_WSD_SETTINGS_CHANGED = 2346
    CMD_WSD_SET_PROGRAM_SETTINGS = 2309
    CMD_WSD_SET_WSM_USER = 2306
    CMD_WSD_START_PREVIEW = 2312
    CMD_WSD_START_PROGRAM = 2307
    CMD_WSD_STOP_PREVIEW = 2315
    CMD_WSD_STOP_PROGRAM = 2308
    CMD_WSM_GENERAL_SETTINGS = 2059
    CMD_WSM_LED_CONTROL = 2058
    CMD_WSM_MODE = 2048
    CMD_WSM_MOTOR = 2050
    CMD_WSM_PRESSURE_MVT_GET = 2051
    CMD_WSM_RAW_DATA_GET = 2057
    CMD_WSM_USER_GET = 2055
    CMD_WSM_USER_SET = 2054
    CMD_WSM_VALVE = 2049
    CMD_WSM_VASISTAS_GET = 2056
    CMD_WSM_ZERO_GET = 2052
    CMD_WUP_DEVICE_SET = 342
    CMD_ZMETER = 525


@unique
class Type(Enum):
    TYPE_ACCOUNT_KEY = 309
    TYPE_ACTIVITY_LAP = 2436
    TYPE_ACTIVITY_PAUSE = 2438
    TYPE_ACTIVITY_SUBCATEGORY = 2409
    TYPE_ADC = 522
    TYPE_ADV_KEY = 310
    TYPE_ALARM = 1298
    TYPE_ALARM_ENABLED = 2329
    TYPE_ALARM_ID = 294
    TYPE_ALARM_SET_SIMPLE = 1291
    TYPE_ALGORITHM_VERSION = 329
    TYPE_ALGO_PARAM = 2489
    TYPE_ALTIMETER_COMPENSATION = 2432
    TYPE_AMAZON_AUTH = 2382
    TYPE_AMAZON_CODE_CHALLENGE = 2384
    TYPE_ANCS_CONFIGURATION = 2347
    TYPE_ANCS_STATUS = 2346
    TYPE_ANS_CONFIGURATION = 2361
    TYPE_ANS_STATUS = 2360
    TYPE_APP_PROBE = 298
    TYPE_APP_PROBE_OS_VERSION = 2344
    TYPE_AS6221_MEASURE_RESULT = 2488
    TYPE_ASSOC_TOKEN = 284
    TYPE_AUDIOTEST = 520
    TYPE_BACKLIGHT = 514
    TYPE_BATTERY_PERCENT = 263
    # TYPE_BATTERY_STATE_FACTORY_RET_SAMPLES = 2
    TYPE_BATTERY_STATE_OPT = 2388
    # TYPE_BATTERY_STATE_OPT_VIBRATOR = 1
    TYPE_BATTERY_STATUS = 1284
    TYPE_BATTERY_STATUS_SAMPLES = 2434
    TYPE_BATTERY_VOLTAGE = 292
    TYPE_BLE_LINK_STATUS = 2318
    TYPE_BLE_SHELL_CHALLENGE = 2423
    TYPE_BOOLEAN = 2474
    # TYPE_BOOLEAN_DISABLED = 0
    # TYPE_BOOLEAN_ENABLED = 1
    TYPE_BOOTSTRAP_REDIRECT = 2467
    TYPE_BREATHE_PARAM = 2476
    TYPE_BSSID = 266
    TYPE_CACHE_TYPE = 2408
    TYPE_CALIBRATION_POINT = 2352
    TYPE_CALIBRATION_SESSION = 2332
    TYPE_CALIBRATION_TYPE = 2351
    TYPE_CALORIES = 2391
    TYPE_CAPTURE_SCT01 = 304
    TYPE_CARTRIDGE_EXPIRY_DATE = 2492
    TYPE_CARTRIDGE_STATE = 2478
    TYPE_CBOR_DATA = 2381
    TYPE_CERT_DER = 2468
    TYPE_CHALLENGE_REQUEST = 2422
    TYPE_CLEANSING_MODE_START = 2503
    TYPE_CLEANSING_MODE_STATUS = 2504
    TYPE_CLOCK_DISPLAY_SETTING = 2317
    TYPE_CMDERROR = 272
    TYPE_CMDERROR_ERR_ARG_INVAL = -8
    TYPE_CMDERROR_ERR_ARG_NOT_SET = -9
    TYPE_CMDERROR_ERR_AUTH_ERR = -6
    TYPE_CMDERROR_ERR_BAD_VERSION = -7
    TYPE_CMDERROR_ERR_CMDINVAL = -4
    TYPE_CMDERROR_ERR_CMDUNKN = -3
    TYPE_CMDERROR_ERR_DEVBUSY = -2
    TYPE_CMDERROR_ERR_FAIL = -1
    TYPE_CMDERROR_ERR_NOT_AUTH = -5
    TYPE_COLOR = 2315
    TYPE_COLOR_HSL = 2322
    TYPE_COLOR_HSV = 2323
    TYPE_COLOR_RGB = 2324
    TYPE_COMM_SUPPORT = 288
    TYPE_CONNECT_REASON = 280
    TYPE_CONNECT_RESULT_EXT = 273
    TYPE_COVID_EBID_ECC = 2456
    TYPE_COVID_HELLO_REPORT = 2458
    TYPE_COVID_STATUS_AT_RISK = 2457
    TYPE_CUSTOMIZATION_ID_GET = 2357
    TYPE_CUSTOMIZATION_ID_SET = 2358
    TYPE_CUSTO_SCREEN_METADATA = 328
    TYPE_CYCLE_TRACKING_CYCLE = 2510
    TYPE_CYCLE_TRACKING_START_OF_MENSTRUATION_LOG = 2512
    TYPE_DAC = 523
    TYPE_DBLIB_DUMP = 283
    TYPE_DEBUG_DUMP_ANCHOR = 2424
    TYPE_DEBUG_DUMP_DATA = 285
    TYPE_DEBUG_DUMP_FORMAT = 301
    TYPE_DEBUG_DUMP_IGNORE_DATA = 293
    TYPE_DEBUG_DUMP_MASK = 286
    TYPE_DEBUG_DUMP_TYPE = 287
    TYPE_DEMO_START = 1293
    TYPE_DEVICE_CHALLENGE_REPLY = 2499
    TYPE_DEVICE_CHALLENGE_REQUEST = 2498
    TYPE_DEVICE_CHALLENGE_SIGNATURE = 2500
    TYPE_DIGITAL_CROWN_MOTION_DELTA = 2445
    TYPE_DIGITAL_CROWN_RESOLUTION_PARAMS = 2446
    TYPE_DIGITAL_CROWN_SCALE_FACTOR = 2507
    TYPE_DISP_BEHAVIOR_0 = 2341
    TYPE_DISP_PREFS_0 = 2340
    TYPE_DISTANCE = 2392
    TYPE_DUMP = 531
    TYPE_DURATION = 2395
    TYPE_ECG_WAVE_ITVL = 2475
    TYPE_END_TIME = 2419
    TYPE_EVENT_V1_DEPRECATED = 2378
    TYPE_EVENT_V2 = 2473
    TYPE_FACTORY_MODE = 2425
    TYPE_FACTORY_RESET_MODE = 302
    TYPE_FACTORY_STATE = 300
    TYPE_FACTORY_TEST_DSC = 2501
    TYPE_FEATURE_MASK = 307
    TYPE_FEATURE_TAGS = 2460
    TYPE_FIRMWARE_VERSION = 330
    TYPE_FLUX_SENSOR_MEASURE_RESULT = 2497
    TYPE_FW_CHUNK = 2416
    TYPE_FW_CHUNK_CRC = 2417
    TYPE_FW_CHUNK_REQUEST = 2415
    TYPE_FW_INFO = 2414
    TYPE_GET_NB_MAX_ALARM = 295
    TYPE_GLANCE_STATUS = 2426
    TYPE_GLYPH_ID = 2396
    TYPE_GPIO = 516
    TYPE_GREENTEG_SENSITIVITY_BIN = 2506
    TYPE_HANDS_CAL_START = 1294
    TYPE_HANDS_CAL_STOP = 1295
    TYPE_HANDS_MOVE = 1292
    TYPE_HEARTRATE = 2452
    TYPE_HMAC = 2459
    TYPE_HOME_SCREEN = 2355
    TYPE_HR_AS7000 = 2343
    TYPE_HR_AS7000_STATUS = 2375
    TYPE_HR_AS7000_STOP = 2342
    TYPE_HR_AUTO_ALGORITHM = 314
    TYPE_IAP_WCI = 534
    TYPE_ID = 325
    # TYPE_IFSETTINGS = 269
    # TYPE_IFSETTINGS_DEL = 2
    # TYPE_IFSETTINGS_GET = 1
    # TYPE_IFSETTINGS_REP = 3
    # TYPE_IFSETTINGS_SET = 0
    # TYPE_IFSTATE = 271
    # TYPE_IFSTATE_ERR_FAIL = -1
    # TYPE_IFSTATE_ERR_OK = 0
    # TYPE_IFSTATE_ERR_UNKNOWNIF = -2
    # TYPE_IFSTATE_GET = 1
    # TYPE_IFSTATE_IFETH = 1
    # TYPE_IFSTATE_RUNNING = 2
    # TYPE_IFSTATE_SET = 0
    # TYPE_IFSTATE_UP = 1
    TYPE_IMAGE_DATA = 2398
    TYPE_IMAGE_METADATA = 2397
    TYPE_INACTIVITY_CFG = 2477
    TYPE_INFO_TYPE = 2394
    TYPE_INT32 = 535
    TYPE_IP = 265
    TYPE_IP_SETTINGS = 261
    TYPE_IS_CARTRIDGE_INSERTED = 2484
    TYPE_IS_HOOD_OPENED = 2485
    TYPE_KEY = 2455
    TYPE_LAMP_STATE = 2316
    TYPE_LAP_NB = 2387
    TYPE_LCD = 515
    TYPE_LIGHT_SENSOR_REPLY = 2356
    TYPE_LIVE_HR = 2369
    TYPE_LOCALE = 289
    TYPE_LOCAL_NOTIFICATION = 2472
    TYPE_LULLABY = 7
    TYPE_LUMINOSITY_LEVEL = 2359
    TYPE_MAC = 1043
    TYPE_MAC_BYTES = 2483
    TYPE_MAX8614X_CHANNEL_CONFIG = 2481
    TYPE_MAX8614X_CHANNEL_STATS = 2480
    TYPE_MAX8614X_FACTORY_STATS = 2444
    TYPE_MAX8614X_FACTORY_STATS_PARAMS = 2447
    TYPE_MAX8614X_R = 2482
    TYPE_MAX86173_CHANNEL_STATS = 2505
    TYPE_MAX8617X_CHANNEL_STATS = 2486
    TYPE_MCP3422_MEASURE_RESULT = 2487
    TYPE_MCU_ID = 311
    TYPE_MEASURE_CATEGORY = 2427
    TYPE_MEASURE_LIVE_APP_STATUS = 2463
    TYPE_MEASURE_LIVE_ECG = 2429
    TYPE_MEASURE_LIVE_META = 2428
    TYPE_MEASURE_PROCESS_STEP = 2435
    TYPE_MEASURE_STOP_REASON = 2430
    # TYPE_MEDIA = 6
    # TYPE_MOOD = 1
    TYPE_MTU_ATT_BLE = 2450
    TYPE_MTU_TLS = 2449
    TYPE_MTU_WPP = 2448
    TYPE_NAME = 1300
    # TYPE_NAP = 2
    TYPE_NETUPDATE_PROGRESS = 1040
    TYPE_NETUPDATE_REBOOT = 1042
    TYPE_NETUPDATE_RESULT = 1041
    TYPE_NO2_ACQ_FREQ = 2393
    TYPE_NO2_CAL = 2383
    TYPE_NO2_CAL_MEASURE = 2385
    TYPE_NOTIFICATIONS_DISPLAY_STATE = 2471
    TYPE_NOTIFICATION_APP_DISPLAY_INFO = 2405
    TYPE_NOTIFICATION_APP_HASH_ID_CRC32 = 2407
    TYPE_NOTIFICATION_APP_HASH_ID_VERSION = 2406
    # TYPE_NOTIFICATION_APP_HASH_ID_VERSION_CRC32 = 0
    TYPE_NOTIFICATION_APP_ID = 2404
    TYPE_NOTIFICATION_APP_INFO = 2403
    TYPE_NULL = 256
    TYPE_PACE = 2411
    TYPE_PAUSE_STATE = 2439
    TYPE_PERCENTILE = 2433
    TYPE_PERSO = 517
    TYPE_PLS_RETURN_CODE = 296
    TYPE_PLS_STATION = 297
    TYPE_PRESSURE_TEMPERATURE = 2431
    TYPE_PROBE_CHALLENGE = 290
    TYPE_PROBE_CHALLENGE_RESPONSE = 291
    TYPE_PROBE_REPLY = 257
    TYPE_PROGRAM_SETTING = 2326
    TYPE_PROGRAM_TYPE = 2327
    TYPE_RAW_DATA_CMD = 331
    TYPE_RAW_DATA_READ_MODE = 2402
    TYPE_RAW_DATA_STREAM_CONTROL = 2400
    TYPE_REBOOT_OPTIONAL = 2443
    TYPE_REBOOT_REASON = 2442
    TYPE_RESPONSIVE_LIGHT_MODE = 2325
    TYPE_RETAIL = 5
    TYPE_RETURN_CODE = 2328
    TYPE_RH_TEMP = 315
    TYPE_RTC = 529
    TYPE_SCALE_MEDAPP_USER_INFO = 308
    TYPE_SCALE_SESSION = 274
    TYPE_SCREEN_LIST = 1302
    # TYPE_SCREEN_LIST_EMBEDDED_ID_NULL = 0
    # TYPE_SCREEN_LIST_USERID_ALLTIME = 0
    TYPE_SCREEN_STATE = 2389
    TYPE_SELFTEST = 532
    TYPE_SEND_ENV_MEASURE = 2338
    TYPE_SENSOR_ID = 312
    TYPE_SETTINGS_CHANGED = -32767
    TYPE_SET_CLOCK_MODE = 2314
    TYPE_SET_TIME = 1296
    TYPE_SHORTCUT_ACTION = 2465
    TYPE_SHORTID = 2470
    TYPE_SIGNAL_DATA = 2386
    TYPE_SIGNAL_HEADER = 2380
    TYPE_SIGNAL_TYPE = 2379
    TYPE_SILENT = 322
    TYPE_SKIN_TEMPERATURE_MEASURE_RESULT = 2496
    TYPE_SKIP_ASSOC = 275
    TYPE_SLEEP = 3
    TYPE_SLEEP_ACTIVITY = 2377
    TYPE_SLEEP_ACTIVITY_GET = 2376
    TYPE_SLOT = 533
    TYPE_SN19020X6_MEASURE_RESULT = 2495
    TYPE_SOFTDEVICE_VERSION = 313
    TYPE_SPEED = 2413
    TYPE_SPIFLASH = 528
    TYPE_SPI_FLASH_CHUNK = 2373
    TYPE_SPI_FLASH_CMD = 2372
    TYPE_STAIRS = 2490
    TYPE_START_TIME = 2418
    TYPE_STATUS = 2420
    TYPE_STATUS_CHANGED = 0x8000
    TYPE_STEPS = 2390
    TYPE_STORED_MEASURE_ACTION = 276
    TYPE_STORED_MEASURE_DATA = 279
    TYPE_STORED_MEASURE_DATA_EXTEND_POS = 2451
    TYPE_STORED_MEASURE_META = 278
    TYPE_STORED_MEASURE_META_EXTEND = 299
    TYPE_STORED_MEASURE_STATUS = 277
    TYPE_STORED_SIGNAL_DATA = 324
    TYPE_STORED_SIGNAL_META = 323
    TYPE_STORED_SIGNAL_META_EXTEND = 326
    TYPE_STRING = 519
    TYPE_STRIP_COUNT = 2479
    TYPE_SWIM_POOL_SIZE = 2321
    TYPE_SWIM_STATUS = 2331
    TYPE_SYMPTOM_LIST_ITEM = 2509
    TYPE_SYMPTOM_TYPE = 2508
    TYPE_SYMPTOM_TYPE_CYCLE = 1
    TYPE_SYNC_REQUEST = 320
    TYPE_TAPPING_STATUS = 2330
    TYPE_TEMP_CAL_REPLY = 2350
    TYPE_TEMP_CAL_SET = 2349
    TYPE_TEST_SCREEN = 2421
    TYPE_THRESHOLD = 2469
    # TYPE_THRESHOLD_HR_HIGH = 1
    # TYPE_THRESHOLD_HR_LOW = 2
    # TYPE_THRESHOLD_INVALID = 0
    TYPE_TIMESTAMP = 2410
    TYPE_TIME_COUNTERS = 2371
    TYPE_TIME_SET = 1281
    TYPE_TIME_SET_REPLY = 1282
    TYPE_TMP117_MEASURE_RESULT = 2494
    TYPE_TRACKER_GOAL = 1297
    TYPE_TRACKER_MOVE_HANDS = 2491
    TYPE_TRACKER_USER = 1283
    TYPE_TRACKER_WEAR_POS = 303
    TYPE_UDI = 2437
    TYPE_UINT32 = 518
    TYPE_UINT64 = 536
    TYPE_UNIT_CONVERSION_PARAMETERS = 327
    TYPE_UNKNOWN_STEPS = 2370
    TYPE_UP_FIRMWARE_START = 1025
    TYPE_USER_ACTION = 2368
    TYPE_USER_INFO = 282
    TYPE_USER_SECRET = 1299
    TYPE_USER_UNIT = 281
    TYPE_VASISTAS_ACTIVITY_STATUS = 2348
    TYPE_VASISTAS_ACTI_RECO_V1_V2 = 1547
    TYPE_VASISTAS_AHI = 2464
    TYPE_VASISTAS_CBT = 2502
    TYPE_VASISTAS_FLAGS = 2461
    TYPE_VASISTAS_HEARTRATE = 2345
    TYPE_VASISTAS_SPO2 = 2453
    TYPE_VASISTAS_SWIM_TYPE = 1549
    TYPE_VASISTAS_SWIM_V1 = 1545
    TYPE_VASISTAS_TYPE = 1301
    TYPE_VASISTAS_UNCERTAIN_SWIM = 1548
    TYPE_VASISTAS_WRIST_HR = 2353
    TYPE_VASISTAS_WRIST_TEMP = 2354
    TYPE_VERSION = 2401
    TYPE_VIBRATOR_PATTERN = 2374
    TYPE_VIBRATOR_SET_SIMPLE = 2511
    TYPE_WAKEUP = 4
    TYPE_WAM_AUTO_SLEEP = 1290
    TYPE_WAM_DAILY_ACTIVITIES = 1287
    TYPE_WAM_DISPLAYED_INFO = 1285
    TYPE_WAM_RAW_DATA_GET = 1288
    TYPE_WAM_SCREENS_LIST = 1289
    TYPE_WAM_VASISTAS_AWAKE = 1539
    TYPE_WAM_VASISTAS_DURATION = 1538
    TYPE_WAM_VASISTAS_GET = 1286
    TYPE_WAM_VASISTAS_HEAD = 1537
    TYPE_WAM_VASISTAS_MET_CAL = 1544
    TYPE_WAM_VASISTAS_MET_CAL_EARNED = 1546
    TYPE_WAM_VASISTAS_RUN = 1541
    TYPE_WAM_VASISTAS_SLEEP = 1543
    TYPE_WAM_VASISTAS_SLEEP_DBG = 1542
    TYPE_WAM_VASISTAS_WALK = 1540
    TYPE_WEIGHTTEST = 521
    TYPE_WEIGHT_CAL = 524
    TYPE_WEIGHT_VERIF = 530
    # TYPE_WIFI_ANT = 513
    # TYPE_WIFI_AP_CONNECT = 260
    # TYPE_WIFI_AP_SCAN = 259
    # TYPE_WIFI_CONNECT_RESULT = 262
    # TYPE_WIFI_COUNTRY = 264
    # TYPE_WIFI_DELAY = 268
    # TYPE_WIFI_ENABLE = 270
    # TYPE_WIFI_ENABLE_FALSE = 0
    # TYPE_WIFI_ENABLE_TRUE = 1
    # TYPE_WIFI_SCAN_PARAM = 258
    TYPE_WL = 525
    TYPE_WORKOUT_FACE_MODE = 2412
    TYPE_WORKOUT_GPS_STATUS = 321
    TYPE_WORKOUT_LAP_STATE = 2440
    TYPE_WORKOUT_MAX_NUMBER = 2493
    TYPE_WORKOUT_SCREEN_GLYPH_DATA = 318
    TYPE_WORKOUT_SCREEN_LIST = 316
    TYPE_WORKOUT_SCREEN_METADATA = 317
    TYPE_WORKOUT_SCREEN_NAME = 319
    TYPE_WORKOUT_TOTAL_DIFF = 2441
    TYPE_WPAKEY = 267
    TYPE_WPM_FACTORY_GETPRESSURE = 1913
    TYPE_WPM_FACTORY_GETZERO = 1917
    TYPE_WPM_FACTORY_SETMOTOR = 1912
    TYPE_WPM_FACTORY_SETVALVE = 1911
    TYPE_WPM_MODE = 1888
    TYPE_WPM_START = 1889
    TYPE_WPM_STS_BP_EVENT = 1894
    TYPE_WPM_STS_BP_PULSE = 1893
    TYPE_WPM_STS_BP_RESULT = 1892
    TYPE_WPM_STS_PRESSURE = 1923
    TYPE_WPP_EVT_SUPPORT = 2320
    TYPE_WSD_ALARM = 2308
    TYPE_WSD_PROGRAM_ID = 2312
    TYPE_WSD_PROGRAM_INFO = 2313
    TYPE_WSD_PROGRAM_SETTINGS = 2310
    TYPE_WSD_SCAN_WSM_FINISH = 2306
    TYPE_WSD_SCAN_WSM_RESULT = 2305
    TYPE_WSD_SET_WSM_USER_RESULT = 2309
    TYPE_WSD_STATUS = 2311
    TYPE_WSD_SUBPROGRAM = 2333
    TYPE_WSD_SUBSTATUS = 2319
    TYPE_WSD_WSM_USER = 2307
    TYPE_WSM_LED_CONTROL = 2058
    TYPE_WSM_MODE = 2048
    TYPE_WSM_MOTOR = 2050
    TYPE_WSM_PRESSURE_MVT_GET = 2051
    TYPE_WSM_PRIVATE_MODE = 2059
    TYPE_WSM_RAW_DATA_GET = 2057
    TYPE_WSM_USER = 2055
    TYPE_WSM_VALVE = 2049
    TYPE_WSM_VASISTAS_DURATION = 2065
    TYPE_WSM_VASISTAS_GENERAL = 2066
    TYPE_WSM_VASISTAS_GENERAL_V2 = 2067
    TYPE_WSM_VASISTAS_GET = 2056
    TYPE_WSM_VASISTAS_HEAD = 2064
    TYPE_WSM_ZERO_GET = 2052
    TYPE_ZMETER = 526
    TYPE_ZMETER_CAL = 527


################# TYPES #################


# MacAddress = Annotated[str, Len(17, 17)]
RandomChallenge = Annotated[bytes, Len(16, 16), Strict()]
SHA1Hash = Annotated[bytes, Len(20, 20), Strict()]
UINT8 = Annotated[int, Interval(ge=0, le=0xFF)]
UINT16 = Annotated[int, Interval(ge=0, le=0xFFFF)]
UINT32 = Annotated[int, Interval(ge=0, le=0xFFFFFFFF)]
BOOL = Annotated[int, Interval(ge=0, le=1)]


class WppType(BaseModel, ABC):
    TYPE_MAP: ClassVar[Dict[Type, typing.Type["WppType"]]] = {}

    def __init_subclass__(cls, **kwargs):
        WppType.TYPE_MAP[cls.ID()] = cls
        return super().__init_subclass__(**kwargs)

    @staticmethod
    @abstractmethod
    def ID() -> Type:
        raise NotImplementedError()

    @staticmethod
    def _size_from_metadata(ty: Type) -> Tuple[int, bool]:
        for info in ty.__metadata__:
            if isinstance(info, Interval):
                return ((info.le - info.ge).bit_length() + 7) // 8, info.ge < 0

        raise RuntimeError(f'size unknown for {ty}')

    def serialize(self) -> bytes:
        data = b""
        for name, ty in get_annotations(self.__class__).items():
            val = getattr(self, name)
            if val is None:
                continue
            if isinstance(val, bytes):
                assert len(val) < 256
                data += struct.pack(f">{len(val) + 1}p", val)
            elif isinstance(val, int):
                # we *must* have metadata for the size
                size, signed = WppType._size_from_metadata(ty)
                data += val.to_bytes(size, "big", signed=signed)
            elif isinstance(val, str):
                val = val.encode()
                assert len(val) < 256
                data += struct.pack(f">{len(val) + 1}p", val)
            else:
                # hope it has one of these!
                data += val.serialize()

        return struct.pack(f">HH", self.ID().value, len(data)) + data

    @classmethod
    def deserialize(cls, ty: Type, data: bytes) -> "WppType":
        subcls = cls.TYPE_MAP[ty]
        kwargs = {}

        # serially pull data in order
        # validation will be from pydantic
        for name, ty in get_annotations(subcls).items():
            size = None
            real_type = ty
            if get_origin(ty) is Annotated:
                real_type = get_args(ty)[0]
            else:
                real_type = ty

            if issubclass(real_type, bytes):
                size = data[0] + 1
                kwargs[name] = data[1:size]
            elif issubclass(real_type, int):
                # we *must* have metadata for the size
                size, signed = WppType._size_from_metadata(ty)
                kwargs[name] = int.from_bytes(data[:size], "big", signed=signed)
            elif issubclass(real_type, (int, date, datetime)):
                size = 4
                kwargs[name] = datetime.utcfromtimestamp(
                    int.from_bytes(data[:size], "big")
                )
            elif issubclass(real_type, str):
                size = data[0] + 1
                kwargs[name] = data[1:size].decode()
            else:
                # hope it has one of these!
                size = real_type.deserialize(data)

            data = data[size:]

        return subcls(**kwargs)


class ProbeChallengeResponse(WppType):
    answer: SHA1Hash

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_PROBE_CHALLENGE_RESPONSE


class ProbeChallenge(WppType):
    mac: MacAddress
    challenge: RandomChallenge

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_PROBE_CHALLENGE

    def make_response(self, kl_secret: str) -> ProbeChallengeResponse:
        m = hashlib.sha1()
        m.update(self.challenge)
        m.update(self.mac.encode())
        m.update(kl_secret.encode())
        return ProbeChallengeResponse(answer=m.digest())


class ProbeReply(WppType):
    vid: UINT16
    pid: UINT16
    name: str
    mac: MacAddress
    secret: str
    hard_version: UINT32
    mfg_id: str
    bl_version: UINT32
    soft_version: UINT32
    rescue_version: UINT32

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_PROBE_REPLY


class FactoryState(WppType):
    value: UINT8

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_FACTORY_STATE


class BatteryStatus(WppType):
    percent: UINT8
    state: UINT8
    mv: UINT32
    reserved: UINT32

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_BATTERY_STATUS


class TrackerUser(WppType):
    uid: UINT32
    weight_g: UINT32
    height_cm: UINT32
    gender: UINT8
    birth: datetime
    first_name: str

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_TRACKER_USER


class Null(WppType):
    @staticmethod
    def ID() -> Type:
        return Type.TYPE_NULL


class DebugDumpAnchor(WppType):
    value: UINT32

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_DEBUG_DUMP_ANCHOR


@unique
class DebugMask(IntFlag):
    DBLIB_DUMP = 1
    WLOG = 2
    BATTMEAS = 4
    USERFEEDBACK = 8
    RAWDATA = 0x10
    WPP = 0x20
    SIGNAL = 0x40
    DBLIB_PERSONAL_DATA = 0x80
    DBLIB_FORCE_DUMP_ALL = 0x100
    HWA09_RAWDATA_ADXL = 0x10000
    HWA09_RAWDATA_ADXL_WORKOUT = 0x20000
    HWA09_RAWDATA_MAX8614 = 0x40000
    HWA09_RAWDATA_MAX8614_WORKOUT = 0x80000
    HWA09_RAWDATA_SLEEP = 0x100000
    HWA09_RAWDATA_SWIM_ALGO = 0x200000
    HWA09_RAWDATA_PPG_ALGO = 0x400000
    HWA09_RAWDATA_STEPS_ALGO = 0x800000
    HWA09_RAWDATA_PRESSURE = 0x1000000
    HWA09_RAWDATA_ECG = 0x2000000
    HWA09_RAWDATA_OTHERS = 0x4000000
    HWA09_RAWDATA_WORKOUT_ACTIVITY = 0x8000000
    HWA09_RAWDATA_PPG_BACKGROUND = 0x10000000


class DebugDumpMask(WppType):
    mask: Annotated[DebugMask, Interval(ge=0, le=0xFFFFFFFF)]

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_DEBUG_DUMP_MASK


class DebugDumpData(WppType):
    buf: Annotated[bytes, Strict()]  # likely a max of 64B?

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_DEBUG_DUMP_DATA


@unique
class DebugDumpTypeEnum(IntEnum):
    NONE = 0
    DBLIB = 3
    RAW = 5
    WLOG = 7


class DebugDumpType(WppType):
    type: Annotated[DebugDumpTypeEnum, Interval(ge=0, le=0xFFFFFFFF)]
    size: UINT32

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_DEBUG_DUMP_TYPE


@unique
class RawDataReadModeEnum(IntEnum):
    WPP_RAW_DATA_READ_ALL = 0
    WPP_RAW_DATA_READ_NOT_SENT = 1
    WPP_RAW_DATA_READ_FROM_OLDEST = 2
    WPP_RAW_DATA_READ_FROM_TIMESTAMP = 3  # any value past this one?


class RawDataReadMode(WppType):
    mode: Annotated[RawDataReadModeEnum, Interval(ge=0, le=0xFFFFFFFF)]

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_RAW_DATA_READ_MODE


class BatteryPercent(WppType):
    percent: UINT16

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_BATTERY_PERCENT


class BatteryVoltage(WppType):
    mv: UINT16

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_BATTERY_VOLTAGE


class BatteryStateOpt(WppType):
    opt: UINT32

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_BATTERY_STATE_OPT


class SpiFlashCmd(WppType):
    _sbz: UINT32 = 0
    addr: UINT32
    len: UINT32
    _unused: UINT32 = 0

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_SPI_FLASH_CMD


class SpiFlashChunk(WppType):
    data: Annotated[bytes, Len(16, 16), Strict()]

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_SPI_FLASH_CHUNK


class SwimStatus(WppType):
    enabled: BOOL

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_SWIM_STATUS


class Gpio(WppType):
    cmd: Annotated[int, Interval(ge=0, le=1)] # 0 is write cfg, 1 is write cfg then read val? 1 can't be used with mode #7
    bank: Annotated[int, Interval(ge=0, le=1)]
    pin: Annotated[int, Interval(ge=0, le=1)]
    # 2 is invalid, 0 -> OUT_2mA, 1 -> OUT_HI-Z_1, 3 -> IN_PULL_UP, 4 -> OUT_10mA, 5 -> IN, 6 -> IN_PULL_DOWN, 7 -> UNUSED
    gpio_mode: Annotated[int, Interval(ge=0, le=7)]
    value: Annotated[int, Interval(ge=0, le=1)]
    err: Annotated[int, Interval(ge=-128, le=127)]

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_GPIO


@unique
class WppErrorEnum(IntEnum):
    ARG_NOT_SET = -9
    ARG_INVAL = -8
    BAD_VERSION = -7
    AUTH_ERR = -6
    NOT_AUTH = -5
    CMDINVAL = -4
    CMDUNKN = -3
    DEVBUSY = -2
    FAIL = -1


class WppError(WppType):
    # cmd: Annotated[Cmd, Interval(ge=0, le=0xffff)]
    cmd: UINT16
    err: Annotated[WppErrorEnum, Interval(ge=-0x80000000, le=0x7FFFFFFF)]

    @staticmethod
    def ID() -> Type:
        return Type.TYPE_CMDERROR


################# COMMANDS #################


class WppCmd(BaseModel, ABC):
    CMD_MAP: ClassVar[Dict[Cmd, typing.Type["WppCmd"]]] = {}

    def __init_subclass__(cls, **kwargs):
        WppCmd.CMD_MAP[cls.ID()] = cls
        return super().__init_subclass__(**kwargs)

    @staticmethod
    @abstractmethod
    def ID() -> Cmd:
        raise NotImplementedError()

    def serialize(self) -> bytes:
        data = b""
        for name, ty in get_annotations(self.__class__).items():
            val = getattr(self, name)
            if val is None:
                continue
            if isinstance(val, list):
                for item in val:
                    data += item.serialize()
                continue

            data += val.serialize()

        return struct.pack(f">BHH", 1, self.ID().value, len(data)) + data

    @staticmethod
    def decode_header(data: bytes) -> Tuple[Cmd, int, bool]:
        flag, cmd, l = struct.unpack_from(f">BHH", data)
        assert flag == 1
        slave_req = bool(cmd & Cmd.CMD_CHANNEL_SLAVE_REQUEST.value)
        cmd = cmd & ~Cmd.CMD_CHANNEL_SLAVE_REQUEST.value
        return Cmd(cmd), l + 5, slave_req

    @classmethod
    def deserialize(cls, data: bytes) -> "WppCmd":
        cmd, l, slave_req = WppCmd.decode_header(data)
        assert l == len(data)
        data = data[5:]
        subcls = cls.CMD_MAP[cmd]
        kwargs = {}

        # build a reverse type ID -> name map
        TYPE_MAP = {}
        for name, ty in get_annotations(subcls).items():
            origin = get_origin(ty)
            if origin is Union or origin is list:
                ty = get_args(ty)[0]
                if origin is list:
                    kwargs[name] = list()
            TYPE_MAP[ty.ID()] = name

        # find each type, deserialize it, and stick it into kwargs
        while data:
            typeid, typelen = struct.unpack_from(f">HH", data)
            typeid = Type(typeid)
            val = WppType.deserialize(typeid, data[4 : 4 + typelen])
            name = TYPE_MAP[typeid]
            existing = kwargs.get(name)
            if existing is not None:
                if isinstance(existing, list):
                    existing.append(val)
                else:
                    raise AttributeError(
                        f"{name} is not a list but value already assigned to {existing}"
                    )
            else:
                kwargs[name] = val
            data = data[4 + typelen :]

        return subcls(**kwargs)

    def merge_from(self, other):
        assert type(self) == type(other)
        for name, ty in get_annotations(type(self)).items():
            new = getattr(other, name)
            if new is None:
                continue
            old = getattr(self, name)
            if get_origin(ty) is list:
                old.extend(new)
                continue
            if old is not None:
                raise AttributeError(
                    f"{name} is not a list but value already assigned to {old}"
                )
            setattr(self, name, new)


class CmdProbe(WppCmd):
    # AppProbe
    # AppProbeOsVersion
    response: Optional[ProbeChallengeResponse] = None
    reply: Optional[ProbeReply] = None
    factory_state: Optional[FactoryState] = None

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_PROBE


class CmdProbeChallenge(WppCmd):
    response: Optional[ProbeChallengeResponse] = None
    challenge: ProbeChallenge

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_PROBE_CHALLENGE


class CmdTrackerUserGet(WppCmd):
    user: Optional[TrackerUser] = None

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_TRACKER_USER_GET


class CmdDisconnect(WppCmd):
    null: Optional[Null] = None

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_DISCONNECT


class CmdBatteryStatus(WppCmd):
    status: Optional[BatteryStatus] = None

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_BATTERY_STATUS


class CmdDebugSet(WppCmd):
    mask: Optional[DebugDumpMask] = None
    null: Optional[Null] = None

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_DEBUG_SET


class CmdDebugDump(WppCmd):
    anchor: Optional[DebugDumpAnchor] = None
    read_mode: Optional[RawDataReadMode] = None
    type: Optional[DebugDumpType] = None
    data: List[DebugDumpData] = list()
    null: Optional[Null] = None

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_DEBUG_DUMP


class CmdDebugDumpAck(WppCmd):
    null: Optional[Null] = None

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_DEBUG_DUMP_ACK


class CmdBatteryPercent(WppCmd):
    percent: Optional[BatteryPercent] = None
    voltage: Optional[BatteryVoltage] = None

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_BATTERY_PERCENT


class CmdSpiFlash(WppCmd):
    cmd: Optional[SpiFlashCmd] = None

    chunks: List[SpiFlashChunk] = list()
    null: Optional[Null] = None

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_SPI_FLASH


class CmdSwimStatus(WppCmd):
    status: Optional[SwimStatus] = None
    null: Optional[Null] = None

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_SWIM_STATUS_SET


class CmdError(WppCmd):
    error: WppError

    @staticmethod
    def ID() -> Cmd:
        return Cmd.CMD_ERROR

# self tests containing device secrets removed
