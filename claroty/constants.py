""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

ASSET_TYPE = {
    "Endpoint": "eEndpoint",
    "Engineering Station": "eEngineeringStation",
    "Networking": "eNetworking",
    "OT": "eOT",
    "PLC": "ePLC"
}

CRITICALITY_EXACT = {"High": "eHigh", "Medium": "eMedium", "Low": "eLow"}

STATUS_CATEGORY = {
    "Resolved": "1",
    "Unresolved": "0",
    "Security": "1",
    "Integrity": "0"
}
FORMAT = {
    "Asset List": "asset_list",
    "Insight Assets": "insight_assets",
    "Resource IDs": "rids"
}
SEVERITY = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}
ALERT_SEVERITY = {
    "Low": 0,
    "Medium": 1,
    "High": 2,
    "Critical": 3
}

EVENT_STATUS = {
    "OT Alert": "eOtAlert",
    "OT Operation": "eOtOperation",
    "Alert": "eAlert",
    "Not Risky Change": "eNotRisky"
}
TYPE_DICT = {
    "0 - New Asset": "0",
    "1 - Asset Conflict": "1",
    "2 - Baseline Deviation": "2",
    "3 - Threat": "3",
    "4 - Asset Information Change": "4",
    "5 - Protocol Specific": "5",
    "6 - Baseline Down": "6",
    "8 - Baseline Volume Deviation High": "8",
    "9 - Baseline Volume Deviation Low": "9",
    "10 - FTP Data": "10",
    "11 - Baseline Rule": "11",
    "12 - High Arp Activity": "12",
    "13 - Known Threat Event": "13",
    "14 - False Mac": "14",
    "15 - Suspicious File Transfer": "15",
    "16 - Policy Violation": "16",
    "17 - Policy Rule Match": "17",
    "18 - Host Scan": "18",
    "19 - Port Scan": "19",
    "20 - Denial Of Service": "20"
}
