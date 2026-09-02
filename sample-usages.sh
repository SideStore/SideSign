#!/usr/bin/env bash

# 1. Developer Portal Management APIs

# Developer Teams:
./sidesign auth -v teams --server https://ani.some.com --devicedata-password test

# Registered Devices:
# List devices
./sidesign auth -v devices --server https://ani.some.com --devicedata-password test

# Register a new device
./sidesign auth -v devices register --name "My iPad" --udid "<UDID>" --server https://ani.some.com --devicedata-password test

# Rename / Update a device
./sidesign auth -v devices update --udid "<UDID>" --name "My New iPad" --server https://ani.some.com --devicedata-password test

# Disable a device
./sidesign auth -v devices disable --udid "<UDID>" --server https://ani.some.com --devicedata-password test

# Delete a device
./sidesign auth -v devices delete --udid "<UDID>" --server https://ani.some.com --devicedata-password test

# Development Certificates:
# List active certificates
./sidesign auth -v certs --server https://ani.some.com --devicedata-password test

# Create a new certificate & export to .p12
./sidesign auth -v certs create --server https://ani.some.com --devicedata-password test --output-p12 dev.p12 --password secret

# Revoke a certificate by ID
./sidesign auth -v certs revoke --id "<CERT_ID>" --server https://ani.some.com --devicedata-password test

# App IDs (Bundle Identifiers):
# List App IDs
./sidesign auth -v appids --server https://ani.some.com --devicedata-password test

# Register a new App ID
./sidesign auth -v appids register --name "MyApp" --bundle-id "com.example.myapp" --server https://ani.some.com --devicedata-password test

# Delete an App ID
./sidesign auth -v appids delete --id "<APP_ID>" --server https://ani.some.com --devicedata-password test

# App Groups:
# List App Groups
./sidesign auth -v appgroups --server https://ani.some.com --devicedata-password test

# Create a new App Group
./sidesign auth -v appgroups create --name "MyGroup" --group-id "group.com.example.myapp" --server https://ani.some.com --devicedata-password test

# Rename / Update an App Group
./sidesign auth -v appgroups update --id "<GROUP_ID>" --name "My Renamed Group" --server https://ani.some.com --devicedata-password test

# Assign App Group to App ID
./sidesign auth -v appgroups assign --app-id "<APP_ID>" --group-id "<GROUP_ID>" --server https://ani.some.com --devicedata-password test

# Delete an App Group
./sidesign auth -v appgroups delete --id "<GROUP_ID>" --server https://ani.some.com --devicedata-password test

# Provisioning Profiles:
# List existing profiles
./sidesign auth -v profiles --server https://ani.some.com --devicedata-password test

# Download/generate profile for a Bundle ID
./sidesign auth -v profiles download --bundle-id "com.SideStore.SideStore" --output embedded.mobileprovision --server https://ani.some.com --devicedata-password test

# Delete a profile by ID/UUID
./sidesign auth -v profiles delete --id "<PROFILE_ID>" --server https://ani.some.com --devicedata-password test

# 2. Standalone Anisette & Signing APIs

# Acquire Anisette Headers (JSON Output):
./sidesign anisette --server https://ani.some.com --devicedata-password test --json

# PKCS#12 (.p12) Operations:
# Inspect .p12 certificate & private key metadata
./sidesign p12 info --input dev.p12 --password secret

# Extract DER certificate and raw private key
./sidesign p12 extract --input dev.p12 --password secret --output-cert cert.der --output-key key.der

# IPA / App Code Signing:
./sidesign sign app.ipa --p12 dev.p12 --password secret --profile embedded.mobileprovision --output signed.ipa

# Authentication & Session Commands:
# Login with Apple ID (interactive password)
./sidesign dev login --apple-id "developer@example.com"

# Login with explicit password
./sidesign dev login --apple-id "developer@example.com" --password "secret"

# Login with shorthand flags
./sidesign dev login -u "developer@example.com" -p "secret"

# Login with encrypted local session
./sidesign dev login -u "developer@example.com" -p "secret" --encrypt-password "sessionpwd"
./sidesign dev login -u "developer@example.com" -p "secret" -ep "sessionpwd"

# Login with custom session file destination
./sidesign dev login -u "developer@example.com" -p "secret" --session "/path/to/custom_session.json"
./sidesign dev login -u "developer@example.com" -p "secret" -s "/path/to/custom_session.json"

# Login with interactive Anisette server selection
./sidesign dev login -u "developer@example.com" --select-server
./sidesign dev login -u "developer@example.com" -sel

# Login with remote Anisette server & custom ADI credentials
./sidesign dev login -u "developer@example.com" -p "secret" --anisette-url "https://ani.some.com" --machine-password "adipass" --machine-path "machine.dat"
./sidesign dev login -u "developer@example.com" -p "secret" -srv "https://ani.some.com" -mpwd "adipass" -mp "machine.dat"

# Login with remote ODA package
./sidesign dev login -u "developer@example.com" -p "secret" --oda "https://example.com/oda.json"

# Login with local ADI libraries
./sidesign dev login -u "developer@example.com" -p "secret" --local-anisette "/path/to/adi/Libraries"
./sidesign dev login -u "developer@example.com" -p "secret" -l "/path/to/adi/Libraries"

# Login with automatic Anisette failover
./sidesign dev login -u "developer@example.com" -p "secret" --failover --source "https://example.com/servers.json"
./sidesign dev login -u "developer@example.com" -p "secret" -f -src "https://example.com/servers.json"

# Login with strict session isolation
./sidesign dev login -u "developer@example.com" -p "secret" --strict
./sidesign dev login -u "developer@example.com" -p "secret" -st

# Re-authenticate active session
./sidesign dev relogin
./sidesign dev relogin --session "/path/to/custom_session.json" --password "sessionpwd"
./sidesign dev relogin -s "/path/to/custom_session.json" -p "sessionpwd"

# Session status check
./sidesign dev status
./sidesign dev status --session "/path/to/custom_session.json" --password "sessionpwd"
./sidesign dev status -s "/path/to/custom_session.json" -p "sessionpwd"

# List saved sessions (aliases: list, sessions, ls)
./sidesign dev list
./sidesign dev sessions
./sidesign dev ls

# Select default team by list index
./sidesign dev select-team 1
./sidesign dev set-team 1

# Select default team by Team ID
./sidesign dev select-team-id TEAM123456
./sidesign dev set-team-id TEAM123456

# Logout of active session
./sidesign dev logout
./sidesign dev logout --session "/path/to/custom_session.json"
./sidesign dev logout -t 1
./sidesign dev logout -tid TEAM123456

# Developer Portal Subcommands with Team Selection:
# List teams for account
./sidesign dev teams
./sidesign dev teams -s "/path/to/custom_session.json"

# Devices management with team index or Team ID
./sidesign dev devices list --using-team 1
./sidesign dev devices list -t 1
./sidesign dev devices list --using-team-id TEAM123456
./sidesign dev devices list -tid TEAM123456
./sidesign dev devices ls

# Register device with long and short flags
./sidesign dev devices register --name "My iPhone" --udid "00008101-001234567890001E"
./sidesign dev devices register -n "My iPhone" -u "00008101-001234567890001E"
./sidesign dev devices add -n "My iPhone" -i "00008101-001234567890001E"

# Rename / update device with aliases
./sidesign dev devices update --udid "00008101-001234567890001E" --name "Renamed iPhone"
./sidesign dev devices rename -u "00008101-001234567890001E" -n "Renamed iPhone"

# Disable device
./sidesign dev devices disable --udid "00008101-001234567890001E"
./sidesign dev devices disable -u "00008101-001234567890001E"

# Delete device with aliases
./sidesign dev devices delete --udid "00008101-001234567890001E"
./sidesign dev devices remove -u "00008101-001234567890001E"
./sidesign dev devices rm -i "00008101-001234567890001E"

# Certificates management:
# List certificates with team selector
./sidesign dev certs list
./sidesign dev certs list -t 1
./sidesign dev certs list -tid TEAM123456
./sidesign dev certs ls

# Create development certificate (auto keypair + portal submit)
./sidesign dev certs create
./sidesign dev certs create --output "dev.cer"
./sidesign dev certs create -o "dev.cer" -t 1

# Revoke certificate with aliases
./sidesign dev certs revoke --id "ABC123XYZ0"
./sidesign dev certs rm -i "ABC123XYZ0"
./sidesign dev certs delete -i "ABC123XYZ0"

# App IDs management:
# List App IDs
./sidesign dev appids list
./sidesign dev appids list -t 1
./sidesign dev appids ls

# Register App ID with long and short flags
./sidesign dev appids register --name "MyApp" --bundle-id "com.example.myapp"
./sidesign dev appids register -n "MyApp" -b "com.example.myapp"
./sidesign dev appids add -n "MyApp" -i "com.example.myapp" -t 1

# Delete App ID with aliases
./sidesign dev appids delete --id "APP_ID_123"
./sidesign dev appids remove -i "APP_ID_123"
./sidesign dev appids rm -i "APP_ID_123"

# App Groups management:
# List App Groups
./sidesign dev appgroups list
./sidesign dev appgroups list -t 1
./sidesign dev appgroups ls

# Create App Group with long and short flags
./sidesign dev appgroups create --name "MyGroup" --group-id "group.com.example.myapp"
./sidesign dev appgroups create -n "MyGroup" -g "group.com.example.myapp"
./sidesign dev appgroups add -n "MyGroup" -gid "group.com.example.myapp"

# Assign App Group to App ID
./sidesign dev appgroups assign --app-id "APP_ID_123" --group-id "group.com.example.myapp"
./sidesign dev appgroups assign -a "APP_ID_123" -g "group.com.example.myapp"
./sidesign dev appgroups assign -aid "APP_ID_123" -gid "group.com.example.myapp"

# Update App Group name
./sidesign dev appgroups update --id "group.com.example.myapp" --name "RenamedGroup"
./sidesign dev appgroups rename -i "group.com.example.myapp" -n "RenamedGroup"

# Delete App Group with aliases
./sidesign dev appgroups delete --id "group.com.example.myapp"
./sidesign dev appgroups remove -g "group.com.example.myapp"
./sidesign dev appgroups rm -i "group.com.example.myapp"

# Provisioning Profiles management:
# List profiles
./sidesign dev profiles list
./sidesign dev profiles list -t 1
./sidesign dev profiles ls

# Download / generate profile for bundle ID
./sidesign dev profiles download --bundle-id "com.example.myapp"
./sidesign dev profiles download --bundle-id "com.example.myapp" --output "dev.mobileprovision"
./sidesign dev profiles download -b "com.example.myapp" -o "dev.mobileprovision"
./sidesign dev profiles fetch -i "com.example.myapp" -o "dev.mobileprovision" -t 1

# Delete profile with aliases
./sidesign dev profiles delete --id "PROFILE_ID_123"
./sidesign dev profiles remove -i "PROFILE_ID_123"
./sidesign dev profiles rm -i "PROFILE_ID_123"

# Standalone Anisette Commands & Permutations:
# Fetch Anisette headers with default server
./sidesign anisette
./sidesign anisette --json
./sidesign anisette -j

# Fetch Anisette headers with specific server
./sidesign anisette --server "https://ani.some.com"
./sidesign anisette -srv "https://ani.some.com" -j

# Fetch Anisette headers with custom ADI data storage & password
./sidesign anisette -srv "https://ani.some.com" --machine-password "secret" --machine-path "adi.dat" -j
./sidesign anisette -srv "https://ani.some.com" -mpwd "secret" -mp "adi.dat" -j

# List public Anisette servers from URL
./sidesign anisette servers
./sidesign anisette servers --source "https://example.com/servers.json"
./sidesign anisette servers -src "https://example.com/servers.json"

# Interactively select server from public list
./sidesign anisette --select-server
./sidesign anisette -sel
./sidesign anisette -sel -j

# Auto-failover Anisette across server list
./sidesign anisette --failover --source "https://example.com/servers.json"
./sidesign anisette -f -src "https://example.com/servers.json" -j
./sidesign anisette -f --start-index 2 -j
./sidesign anisette -f -idx 2 -j

# Fetch Anisette headers via remote ODA package
./sidesign anisette --oda "https://example.com/oda.json"
./sidesign anisette -oda "https://example.com/oda.json" -j

# Fetch Anisette headers via local ADI libraries
./sidesign anisette --local-anisette "/path/to/adi/Libraries"
./sidesign anisette -l "/path/to/adi/Libraries" -j

# Fetch Anisette headers in strict mode
./sidesign anisette -srv "https://ani.some.com" --strict -j
./sidesign anisette -srv "https://ani.some.com" -st -j

# PKCS#12 (.p12) Operations:
# Inspect .p12 metadata
./sidesign p12 info --input dev.p12 --password secret
./sidesign p12 info -i dev.p12 -p secret

# Create .p12 bundle from certificate and private key
./sidesign p12 create --cert cert.der --key private.key --password secret --output dev.p12
./sidesign p12 create -c cert.der -k private.key -p secret -o dev.p12

# Extract DER certificate and private key from .p12
./sidesign p12 extract --input dev.p12 --password secret --output-cert cert.der --output-key key.der
./sidesign p12 extract -i dev.p12 -p secret -oc cert.der -ok key.der

# Certificate Signing Request (CSR):
# Generate RSA 2048-bit keypair and PKCS#10 CSR
./sidesign csr create --name "John Doe" --org "My Org" --country "US" --state "CA" --locality "San Francisco" --output-csr request.csr --output-key private.key
./sidesign csr create -n "John Doe" -o "My Org" -c "US" -s "CA" -l "San Francisco" -oc request.csr -ok private.key

# Code Signing (sign / codesign):
# Sign IPA with P12 and profile
./sidesign sign app.ipa --p12 dev.p12 --password secret --profile dev.mobileprovision --output signed.ipa
./sidesign sign app.ipa -p dev.p12 -pwd secret -m dev.mobileprovision -o signed.ipa

# Sign IPA with interactive password prompt (omit password)
./sidesign sign app.ipa -p dev.p12 -m dev.mobileprovision -o signed.ipa

# Sign IPA with bundle ID override
./sidesign sign app.ipa -p dev.p12 -pwd secret -m dev.mobileprovision --bundle-id "com.example.custom" -o signed.ipa
./sidesign sign app.ipa -p dev.p12 -pwd secret -m dev.mobileprovision -b "com.example.custom" -o signed.ipa

# Sign IPA with custom entitlements
./sidesign sign app.ipa -p dev.p12 -pwd secret -m dev.mobileprovision --entitlements entitlements.plist -o signed.ipa
./sidesign sign app.ipa -p dev.p12 -pwd secret -m dev.mobileprovision -e entitlements.plist -o signed.ipa

# Sign IPA with team resolution
./sidesign sign app.ipa -p dev.p12 -pwd secret -m dev.mobileprovision --using-team 1 -o signed.ipa
./sidesign sign app.ipa -p dev.p12 -pwd secret -m dev.mobileprovision -t 1 -o signed.ipa
./sidesign sign app.ipa -p dev.p12 -pwd secret -m dev.mobileprovision --using-team-id TEAM123456 -o signed.ipa
./sidesign sign app.ipa -p dev.p12 -pwd secret -m dev.mobileprovision -tid TEAM123456 -o signed.ipa

# Sign .app directory bundle
./sidesign sign "Payload/MyApp.app" -p dev.p12 -pwd secret -m dev.mobileprovision

# Sign standalone Mach-O binary or framework / dylib
./sidesign sign "Payload/MyApp.app/MyApp" -p dev.p12 -pwd secret
./sidesign sign "Payload/MyApp.app/Frameworks/MyFramework.framework" -p dev.p12 -pwd secret
./sidesign sign "Payload/MyApp.app/Frameworks/libfoo.dylib" -p dev.p12 -pwd secret

# Code Signature Verification (verify / check):
# Verify IPA signature integrity
./sidesign verify app.ipa
./sidesign check app.ipa

# Verify .app directory
./sidesign verify "Payload/MyApp.app"

# Verify with deep recursion into frameworks and plugins
./sidesign verify app.ipa --deep
./sidesign verify app.ipa -d

# Verify in strict mode
./sidesign verify app.ipa --strict
./sidesign verify app.ipa -s

# Verify with combined deep and strict flags
./sidesign verify app.ipa --deep --strict
./sidesign verify app.ipa -d -s

# Inspection & Display (inspect / display / info / entitlements):
# Inspect binary / bundle overview
./sidesign inspect app.ipa
./sidesign display app.ipa
./sidesign info app.ipa

# Dump embedded entitlements
./sidesign inspect app.ipa --entitlements
./sidesign inspect app.ipa -e
./sidesign entitlements app.ipa

# Dump code signing requirements
./sidesign inspect app.ipa --requirements
./sidesign inspect app.ipa -r

# Combined inspection of entitlements and requirements
./sidesign inspect app.ipa -e -r

# Inspect .app bundle or Mach-O binary directly
./sidesign inspect "Payload/MyApp.app"
./sidesign inspect "Payload/MyApp.app/MyApp" -e

# Provisioning Profile Operations (profile / provision):
# Dump XML metadata and entitlements
./sidesign profile dump embedded.mobileprovision
./sidesign profile dump embedded.mobileprovision -d
./sidesign provision dump embedded.mobileprovision

# Validate profile expiration and structure
./sidesign profile validate embedded.mobileprovision
./sidesign profile validate embedded.mobileprovision -v

# App Extensions (extensions / plugins / appex):
# List app extensions
./sidesign extensions list app.ipa
./sidesign extensions ls app.ipa
./sidesign plugins list "Payload/MyApp.app"
./sidesign appex list app.ipa

# Remove all app extensions to output IPA
./sidesign extensions remove app.ipa --all --output app_no_ext.ipa
./sidesign extensions remove app.ipa -a -o app_no_ext.ipa
./sidesign extensions rm app.ipa -a -o app_no_ext.ipa

# Remove specific app extension by bundle ID
./sidesign extensions remove app.ipa --id "com.example.myapp.widget" --output app_cleaned.ipa
./sidesign extensions remove app.ipa -i "com.example.myapp.widget" -o app_cleaned.ipa
./sidesign extensions rm app.ipa -i "com.example.myapp.widget" -o app_cleaned.ipa

# In-place extension removal
./sidesign extensions remove app.ipa --all
./sidesign extensions remove "Payload/MyApp.app" -i "com.example.myapp.widget"

# Packaging & Archiving (archive / ipa / zip / unzip):
# Unpack IPA into directory
./sidesign archive unzip app.ipa --output Payload/
./sidesign archive unzip app.ipa -o Payload/
./sidesign archive unzip app.ipa
./sidesign unzip app.ipa -o Payload/

# Repack .app into IPA
./sidesign archive zip "Payload/MyApp.app" --output repackaged.ipa
./sidesign archive zip "Payload/MyApp.app" -o repackaged.ipa
./sidesign zip "Payload/MyApp.app" -o repackaged.ipa

# Remove Code Signature (remove-signature / unsign / strip-signature):
# Strip code signature from binary
./sidesign remove-signature "Payload/MyApp.app/MyApp"
./sidesign unsign "Payload/MyApp.app/MyApp"
./sidesign strip-signature "Payload/MyApp.app/MyApp"

# Strip code signature from .app bundle
./sidesign remove-signature "Payload/MyApp.app"

# Global Options applicable across all commands:
# Verbose / trace logging
./sidesign -v dev list
./sidesign --verbose sign app.ipa -p dev.p12 -pwd secret -m dev.mobileprovision -o signed.ipa
./sidesign -v verify app.ipa -d -s
./sidesign -v inspect app.ipa -e

# Version information
./sidesign version
./sidesign --version
./sidesign -v version

# Help information
./sidesign help
./sidesign --help
./sidesign -h
