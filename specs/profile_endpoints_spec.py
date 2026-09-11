CREATE_SPEC = {
    "operation": "CREATE",
    "httpMethod": "POST",
    "endpointType": "Action RPC (request: plist, response: plist)",
    "examples": [
        {
            "purpose": "Generates an ephemeral on-the-fly Xcode Team Provisioning Profile for any Apple platform (defaults to iOS/iPadOS; tvOS/macOS/visionOS via subPlatform). Apple generates a new ID and UUID on each call and does not persist it in the team's profile store (cannot be listed or fetched by ID).",
            "profile-type": [".ephemeral(reason: isTeamProfile=True)"],
            "applicableTo": [".free", ".paid"],
            "endpoint": "https://developerservices2.apple.com/services/QH65B2/ios/downloadTeamProvisioningProfile.action?clientId=XABBG36SBA",
            "requestJson": {
                "clientId": "XABBG36SBA",
                "protocolVersion": "QH65B2",
                "requestId": "REQ00001-0000-0000-0000-000000000001",
                "teamId": "PAIDTEAM01",
                "appIdId": "APPID12345"
            },
            "responseJson": {
                "resultCode": 0,
                "responseId": "RESP0001-0000-0000-0000-000000000001",
                "provisioningProfile": {
                    "provisioningProfileId": "PROFIL0001",
                    "name": "iOS Team Provisioning Profile: com.example.app",
                    "status": "Active",
                    "type": "iOS Development",
                    "distributionMethod": "limited",
                    "UUID": "11111111-1111-1111-1111-111111111111",
                    "version": 3,
                    "dateExpire": "2027-09-11 10:13:29",
                    "managingApp": "Xcode",
                    "isTeamProfile": True,
                    "appIdId": "APPID12345",
                    "certificateIds": ["CERT000001", "CERT000002"],
                    "deviceIds": ["DEVICE0001", "DEVICE0002"],
                    "encodedProfile": "<BINARY_DATA_BASE64>"
                }
            }
        },
        {
            "purpose": "Generates an ephemeral on-the-fly Xcode Team Provisioning Profile for Apple TV (tvOS). Never persisted in team profile store.",
            "profile-type": [".ephemeral(reason: isTeamProfile=True)"],
            "applicableTo": [".free", ".paid"],
            "endpoint": "https://developerservices2.apple.com/services/QH65B2/ios/downloadTeamProvisioningProfile.action?clientId=XABBG36SBA",
            "requestJson": {
                "clientId": "XABBG36SBA",
                "protocolVersion": "QH65B2",
                "requestId": "REQ00002-0000-0000-0000-000000000002",
                "teamId": "PAIDTEAM01",
                "appIdId": "APPID12345",
                "subPlatform": "tvOS"
            },
            "responseJson": {
                "resultCode": 0,
                "provisioningProfile": {
                    "provisioningProfileId": "PROFIL0002",
                    "name": "tvOS Team Provisioning Profile: com.example.app",
                    "status": "Active",
                    "type": "tvOS Development",
                    "distributionMethod": "limited",
                    "subPlatform": "tvOS",
                    "UUID": "22222222-2222-2222-2222-222222222222",
                    "isTeamProfile": True,
                    "encodedProfile": "<BINARY_DATA_BASE64>"
                }
            }
        },
        {
            "purpose": "Create a manual Development or Ad-Hoc provisioning profile with explicit certificates and devices. Stored permanently on Apple servers.",
            "profile-type": [".persistent(reason: isTeamProfile=False)"],
            "applicableTo": [".free", ".paid"],
            "endpoint": "https://developerservices2.apple.com/services/QH65B2/ios/createProvisioningProfile.action?clientId=XABBG36SBA",
            "requestJson": {
                "clientId": "XABBG36SBA",
                "protocolVersion": "QH65B2",
                "requestId": "REQ00005-0000-0000-0000-000000000005",
                "teamId": "PAIDTEAM01",
                "provisioningProfileName": "Custom Dev Profile",
                "appIdId": "APPID12345",
                "distributionType": "limited",
                "certificateIds": ["CERT000001"],
                "deviceIds": ["DEVICE0001"]
            },
            "responseJson": {
                "resultCode": 0,
                "provisioningProfile": {
                    "provisioningProfileId": "PROFIL0004",
                    "name": "Custom Dev Profile",
                    "status": "Active",
                    "type": "iOS Development",
                    "distributionMethod": "limited",
                    "UUID": "44444444-4444-4444-4444-444444444444",
                    "version": 1,
                    "dateExpire": "2027-09-11 10:20:00",
                    "isTeamProfile": False,
                    "certificateIds": ["CERT000001"],
                    "deviceIds": ["DEVICE0001"],
                    "encodedProfile": "<BINARY_DATA_BASE64>"
                }
            }
        },
        {
            "purpose": "Create a manual App Store distribution provisioning profile (deviceIds omitted). Stored permanently on Apple servers.",
            "profile-type": [".persistent(reason: isTeamProfile=False)"],
            "applicableTo": [".paid"],
            "endpoint": "https://developerservices2.apple.com/services/QH65B2/ios/createProvisioningProfile.action?clientId=XABBG36SBA",
            "requestJson": {
                "clientId": "XABBG36SBA",
                "protocolVersion": "QH65B2",
                "requestId": "REQ00006-0000-0000-0000-000000000006",
                "teamId": "PAIDTEAM01",
                "provisioningProfileName": "AppStore Release Profile",
                "appIdId": "APPID12345",
                "distributionType": "store",
                "certificateIds": ["DISTCERT01"]
            },
            "responseJson": {
                "resultCode": 0,
                "provisioningProfile": {
                    "provisioningProfileId": "PROFIL0005",
                    "name": "AppStore Release Profile",
                    "status": "Active",
                    "type": "iOS Distribution",
                    "distributionMethod": "store",
                    "UUID": "55555555-5555-5555-5555-555555555555",
                    "version": 1,
                    "dateExpire": "2027-09-11 10:20:00",
                    "isTeamProfile": False,
                    "certificateIds": ["DISTCERT01"],
                    "encodedProfile": "<BINARY_DATA_BASE64>"
                }
            }
        }
    ]
}

READ_SPEC = {
    "operation": "READ",
    "httpMethod": "POST",
    "endpointType": "Action RPC (request: plist, response: plist)",
    "examples": [
        {
            "purpose": "List persistent provisioning profiles on the team with includeTeamProfiles: True. Note: Ephemeral profiles minted by downloadTeamProvisioningProfile are never stored and cannot be returned here.",
            "profile-type": [".persistent(reason: isTeamProfile=False)"],
            "applicableTo": [".free", ".paid"],
            "endpoint": "https://developerservices2.apple.com/services/QH65B2/ios/listProvisioningProfiles.action?clientId=XABBG36SBA",
            "requestJson": {
                "clientId": "XABBG36SBA",
                "protocolVersion": "QH65B2",
                "requestId": "REQ00003-0000-0000-0000-000000000003",
                "teamId": "PAIDTEAM01",
                "includeTeamProfiles": True
            },
            "responseJson": {
                "resultCode": 0,
                "totalRecords": 1,
                "provisioningProfiles": [
                    {
                        "provisioningProfileId": "PROFIL0003",
                        "name": "Manual Dev Profile",
                        "isTeamProfile": False,
                        "status": "Active",
                        "certificateIds": ["CERT000001"],
                        "deviceIds": ["DEVICE0001"],
                        "encodedProfile": "<BINARY_DATA_BASE64>"
                    }
                ]
            }
        },
        {
            "purpose": "List persistent provisioning profiles on the team with includeTeamProfiles: False.",
            "profile-type": [".persistent(reason: isTeamProfile=False)"],
            "applicableTo": [".free", ".paid"],
            "endpoint": "https://developerservices2.apple.com/services/QH65B2/ios/listProvisioningProfiles.action?clientId=XABBG36SBA",
            "requestJson": {
                "clientId": "XABBG36SBA",
                "protocolVersion": "QH65B2",
                "requestId": "REQ00004-0000-0000-0000-000000000004",
                "teamId": "PAIDTEAM01",
                "includeTeamProfiles": False
            },
            "responseJson": {
                "resultCode": 0,
                "totalRecords": 1,
                "provisioningProfiles": [
                    {
                        "provisioningProfileId": "PROFIL0003",
                        "name": "Manual Dev Profile",
                        "isTeamProfile": False,
                        "status": "Active",
                        "certificateIds": ["CERT000001"],
                        "deviceIds": ["DEVICE0001"],
                        "encodedProfile": "<BINARY_DATA_BASE64>"
                    }
                ]
            }
        },
        {
            "purpose": "Download an existing persistent provisioning profile by its ID. Cannot be used for ephemeral team profiles (Apple returns resultCode 8100).",
            "profile-type": [".persistent(reason: isTeamProfile=False)"],
            "applicableTo": [".free", ".paid"],
            "endpoint": "https://developerservices2.apple.com/services/QH65B2/ios/downloadProvisioningProfile.action?clientId=XABBG36SBA",
            "requestJson": {
                "clientId": "XABBG36SBA",
                "protocolVersion": "QH65B2",
                "requestId": "REQ00007-0000-0000-0000-000000000007",
                "teamId": "PAIDTEAM01",
                "provisioningProfileId": "PROFIL0003"
            },
            "responseJson": {
                "resultCode": 0,
                "provisioningProfile": {
                    "provisioningProfileId": "PROFIL0003",
                    "name": "Manual Dev Profile",
                    "status": "Active",
                    "type": "iOS Development",
                    "UUID": "33333333-3333-3333-3333-333333333333",
                    "isTeamProfile": False,
                    "certificateIds": ["CERT000001"],
                    "deviceIds": ["DEVICE0001"],
                    "encodedProfile": "<BINARY_DATA_BASE64>"
                }
            }
        }
    ]
}

UPDATE_SPEC = {
    "operation": "UPDATE",
    "httpMethod": "POST",
    "endpointType": "Action RPC (request: plist, response: plist)",
    "examples": [
        {
            "purpose": "Regenerate or update an existing persistent profile with modified certificates, devices, or name.",
            "profile-type": [".persistent(reason: isTeamProfile=False)"],
            "applicableTo": [".free", ".paid"],
            "endpoint": "https://developerservices2.apple.com/services/QH65B2/ios/regenProvisioningProfile.action?clientId=XABBG36SBA",
            "requestJson": {
                "clientId": "XABBG36SBA",
                "protocolVersion": "QH65B2",
                "requestId": "REQ00008-0000-0000-0000-000000000008",
                "teamId": "PAIDTEAM01",
                "provisioningProfileId": "PROFIL0003",
                "provisioningProfileName": "Manual Dev Profile",
                "appIdId": "APPID12345",
                "distributionType": "limited",
                "certificateIds": ["CERT000001", "CERT000002"],
                "deviceIds": ["DEVICE0001", "DEVICE0002"]
            },
            "responseJson": {
                "resultCode": 0,
                "provisioningProfile": {
                    "provisioningProfileId": "PROFIL0003",
                    "name": "Manual Dev Profile",
                    "status": "Active",
                    "version": 4,
                    "UUID": "33333333-3333-3333-3333-333333333333",
                    "dateExpire": "2027-09-11 10:30:00",
                    "isTeamProfile": False,
                    "certificateIds": ["CERT000001", "CERT000002"],
                    "deviceIds": ["DEVICE0001", "DEVICE0002"],
                    "encodedProfile": "<BINARY_DATA_BASE64>"
                }
            }
        }
    ]
}

DELETE_SPEC = {
    "operation": "DELETE",
    "httpMethod": "POST",
    "endpointType": "Action RPC (request: plist, response: plist)",
    "examples": [
        {
            "purpose": "Permanently delete a persistent provisioning profile from Apple servers.",
            "profile-type": [".persistent(reason: isTeamProfile=False)"],
            "applicableTo": [".free", ".paid"],
            "endpoint": "https://developerservices2.apple.com/services/QH65B2/ios/deleteProvisioningProfile.action?clientId=XABBG36SBA",
            "requestJson": {
                "clientId": "XABBG36SBA",
                "protocolVersion": "QH65B2",
                "requestId": "REQ00009-0000-0000-0000-000000000009",
                "teamId": "PAIDTEAM01",
                "provisioningProfileId": "PROFIL0003"
            },
            "responseJson": {
                "resultCode": 0,
                "responseId": "RESP0009-0000-0000-0000-000000000009"
            }
        }
    ]
}
