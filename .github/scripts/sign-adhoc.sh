#!/bin/bash
set -euo pipefail
umask 077
: "${P12_B64:?Set IOS_P12_BASE64}" "${PROFILE_B64:?Set IOS_PROFILE_BASE64}"
: "${P12_PASSWORD:?Set IOS_P12_PASSWORD}" "${IPA_PASSWORD:?Set IOS_IPA_PASSWORD}"
tmp=$(mktemp -d "$RUNNER_TEMP/signing.XXXXXX")
keychain="$tmp/build.keychain-db"
profile_dir="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
trap 'security delete-keychain "$keychain" 2>/dev/null || true; rm -rf "$tmp"' EXIT
printf '%s' "$P12_B64" | base64 -D > "$tmp/cert.p12"
printf '%s' "$PROFILE_B64" | base64 -D > "$tmp/profile.mobileprovision"
unset P12_B64 PROFILE_B64
security cms -D -i "$tmp/profile.mobileprovision" > "$tmp/profile.plist"
python3 - "$tmp" <<'PY'
import datetime, pathlib, plistlib, re, sys
tmp = pathlib.Path(sys.argv[1])
profile = plistlib.loads((tmp / 'profile.plist').read_bytes())
ent = profile['Entitlements']
team = profile['TeamIdentifier'][0]
bundle = ent['application-identifier'].split('.', 1)[1]
if not re.fullmatch(r'[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+', bundle):
    sys.exit('Use an explicit App ID in the profile')
if not profile.get('ProvisionedDevices') or ent.get('get-task-allow') or profile.get('ProvisionsAllDevices'):
    sys.exit('Expected an Ad Hoc profile for registered iPhones')
if profile['ExpirationDate'] <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
    sys.exit('Provisioning profile expired')
wanted = plistlib.loads(pathlib.Path('ESPProvisionSample/ESP BLE PROV.entitlements').read_bytes())
for capability, value in wanted.items():
    if ent.get(capability) != value:
        sys.exit(f'Missing App ID capability in profile: {capability}')
uuid = profile['UUID']
project = pathlib.Path('ESPProvisionSample.xcodeproj/project.pbxproj')
source = project.read_text()
# Change the app configurations that declare entitlements, leaving Pods and tests alone.
def configure(match):
    block = match.group()
    if 'CODE_SIGN_ENTITLEMENTS =' not in block:
        return block
    for key, value in {'PRODUCT_BUNDLE_IDENTIFIER': bundle, 'DEVELOPMENT_TEAM': team,
                       'CODE_SIGN_STYLE': 'Manual', 'CODE_SIGN_IDENTITY': '"Apple Distribution"',
                       'PROVISIONING_PROFILE_SPECIFIER': uuid}.items():
        block, count = re.subn(r'(?m)^(\s*' + key + r' = )[^;]+;', lambda m: m[1] + value + ';', block)
        if count != 1:
            sys.exit(f'Unexpected app build settings for {key}')
    return block
patched = re.sub(r'buildSettings = \{.*?\n\s*\};', configure, source, flags=re.S)
if patched == source:
    sys.exit('No app signing configurations found')
project.write_text(patched)
(tmp / 'export.plist').write_bytes(plistlib.dumps(dict(method='release-testing', signingStyle='manual',
    signingCertificate='Apple Distribution', teamID=team, provisioningProfiles={bundle: uuid})))
PY
uuid=$(/usr/libexec/PlistBuddy -c 'Print :UUID' "$tmp/profile.plist")
mkdir -p "$profile_dir"
cp "$tmp/profile.mobileprovision" "$profile_dir/$uuid.mobileprovision"
keypass=$(openssl rand -hex 32)
security create-keychain -p "$keypass" "$keychain"
security unlock-keychain -p "$keypass" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security import "$tmp/cert.p12" -k "$keychain" -P "$P12_PASSWORD" -T /usr/bin/codesign
unset P12_PASSWORD
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keypass" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain" "$HOME/Library/Keychains/login.keychain-db"
xcodebuild -workspace ESPProvisionSample.xcworkspace -scheme ESPProvisionSample -configuration Release \
  -destination 'generic/platform=iOS' -archivePath "$tmp/App.xcarchive" archive
xcodebuild -exportArchive -archivePath "$tmp/App.xcarchive" -exportOptionsPlist "$tmp/export.plist" -exportPath "$tmp/export"
ipas=("$tmp"/export/*.ipa)
test -f "${ipas[0]}"
unzip -q "${ipas[0]}" -d "$tmp/verify"
codesign --verify --deep --strict "$tmp"/verify/Payload/*.app
command -v 7zz >/dev/null || brew install sevenzip
cd "$tmp/export"
7zz a -mhe=on "-p$IPA_PASSWORD" "$RUNNER_TEMP/Voltdeer-iOS.7z" ./*.ipa >/dev/null
