# Bruno Tests Variable Map

This document lists, folder-by-folder, every Bruno test file and for each file which variables are used and which variables are saved to the environment.

Legend:
- Variables used: placeholders like {{var}} referenced in URL, headers, auth, or body.
- Saves: calls to bru.setEnvVar(...) inside tests.

## 1 health
- docs/SellerProof API/1 health/folder.bru — Variables used: none; Saves: none
- docs/SellerProof API/1 health/Health check.bru — Variables used: baseUrl; Saves: none
- docs/SellerProof API/1 health/Health check POST.bru — Variables used: baseUrl; Saves: none
- docs/SellerProof API/1 health/Health check PUT.bru — Variables used: baseUrl; Saves: none
- docs/SellerProof API/1 health/Health check PATCH.bru — Variables used: baseUrl; Saves: none
- docs/SellerProof API/1 health/Health check DELETE.bru — Variables used: baseUrl; Saves: none
- docs/SellerProof API/1 health/Health check 404.bru — Variables used: baseUrl; Saves: none

## 2 auth

### 1 register
- docs/SellerProof API/2 auth/1 register/1 Register success.bru — Variables used: baseUrl, testEmail, testEmailPassword; Saves: none

### 2 login
- docs/SellerProof API/2 auth/2 login/3 Verify Email correct.bru — Variables used: baseUrl, testEmail, validVerificationCode; Saves: none
- docs/SellerProof API/2 auth/2 login/9 User login success verified.bru — Variables used: baseUrl, testEmail, testEmailPassword; Saves: accessToken, refreshToken, testOrgId, userId

### 5 refresh
- docs/SellerProof API/2 auth/5 refresh/4 Refresh token success.bru — Variables used: baseUrl, refreshToken; Saves: accessToken, refreshToken

### switch-organization
- docs/SellerProof API/2 auth/switch-organization/1 Switch organization success.bru — Variables used: baseUrl, accessToken, testOrgId; Saves: accessToken

## 2 auth — 1 register
- [docs/SellerProof API/2 auth/1 register/folder.bru](docs/SellerProof API/2 auth/1 register/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/1 Register success.bru](docs/SellerProof API/2 auth/1 register/1 Register success.bru)
  - Variables used: `{{baseUrl}}`, `{{testEmail}}`, `{{testEmailPassword}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/2 Register second user success.bru](docs/SellerProof API/2 auth/1 register/2 Register second user success.bru)
  - Variables used: `{{baseUrl}}`, `{{secondUserEmail}}`, `{{secondUserPassword}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/3 Register email already exists.bru](docs/SellerProof API/2 auth/1 register/3 Register email already exists.bru)
  - Variables used: `{{baseUrl}}`, `{{testEmail}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/4 Register missing fields.bru](docs/SellerProof API/2 auth/1 register/4 Register missing fields.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/5 Register invalid email.bru](docs/SellerProof API/2 auth/1 register/5 Register invalid email.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/6 Register invalid JSON.bru](docs/SellerProof API/2 auth/1 register/6 Register invalid JSON.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/7 Register password too long.bru](docs/SellerProof API/2 auth/1 register/7 Register password too long.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/8 Register password too short.bru](docs/SellerProof API/2 auth/1 register/8 Register password too short.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/9 Register SQL injection email.bru](docs/SellerProof API/2 auth/1 register/9 Register SQL injection email.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/10 Register SQL injection full_name.bru](docs/SellerProof API/2 auth/1 register/10 Register SQL injection full_name.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/11 Register SQL injection organization_name.bru](docs/SellerProof API/2 auth/1 register/11 Register SQL injection organization_name.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/12 Register SQL injection password.bru](docs/SellerProof API/2 auth/1 register/12 Register SQL injection password.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/13 Register Unicode Chinese.bru](docs/SellerProof API/2 auth/1 register/13 Register Unicode Chinese.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/14 Register Unicode Cyrillic.bru](docs/SellerProof API/2 auth/1 register/14 Register Unicode Cyrillic.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/15 Register Unicode emojis.bru](docs/SellerProof API/2 auth/1 register/15 Register Unicode emojis.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/16 Register Unicode special symbols.bru](docs/SellerProof API/2 auth/1 register/16 Register Unicode special symbols.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/17 Register XSS full_name.bru](docs/SellerProof API/2 auth/1 register/17 Register XSS full_name.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/1 register/18 Register XSS organization_name.bru](docs/SellerProof API/2 auth/1 register/18 Register XSS organization_name.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none

## 2 auth — 2 login
- [docs/SellerProof API/2 auth/2 login/folder.bru](docs/SellerProof API/2 auth/2 login/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/2 auth/2 login/1 User login email not verified.bru](docs/SellerProof API/2 auth/2 login/1 User login email not verified.bru)
  - Variables used: `{{baseUrl}}`, `{{testEmail}}`, `{{testEmailPassword}}`
  - Saves: none
- [docs/SellerProof API/2 auth/2 login/2 Verify Email incorrect.bru](docs/SellerProof API/2 auth/2 login/2 Verify Email incorrect.bru)
  - Variables used: `{{baseUrl}}`, `{{testEmail}}`
  - Saves: none
- [docs/SellerProof API/2 auth/2 login/3 Verify Email correct.bru](docs/SellerProof API/2 auth/2 login/3 Verify Email correct.bru)
  - Variables used: `{{baseUrl}}`, `{{testEmail}}`, `{{validVerificationCode}}`
  - Saves: none
- [docs/SellerProof API/2 auth/2 login/4 Verify Email again.bru](docs/SellerProof API/2 auth/2 login/4 Verify Email again.bru)
  - Variables used: `{{baseUrl}}`, `{{testEmail}}`, `{{validVerificationCode}}`
  - Saves: none
- [docs/SellerProof API/2 auth/2 login/5 Login incorrect email.bru](docs/SellerProof API/2 auth/2 login/5 Login incorrect email.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/2 login/6 Login incorrect password.bru](docs/SellerProof API/2 auth/2 login/6 Login incorrect password.bru)
  - Variables used: `{{baseUrl}}`, `{{testEmail}}`
  - Saves: none
- [docs/SellerProof API/2 auth/2 login/9 User login success verified.bru](docs/SellerProof API/2 auth/2 login/9 User login success verified.bru)
  - Variables used: `{{baseUrl}}`, `{{testEmail}}`, `{{testEmailPassword}}`
  - Saves: [bru.setEnvVar()](docs/SellerProof API/2 auth/2 login/9 User login success verified.bru:29) → `accessToken`; [bru.setEnvVar()](docs/SellerProof API/2 auth/2 login/9 User login success verified.bru:30) → `refreshToken`; [bru.setEnvVar()](docs/SellerProof API/2 auth/2 login/9 User login success verified.bru:31) → `testOrgId`; [bru.setEnvVar()](docs/SellerProof API/2 auth/2 login/9 User login success verified.bru:32) → `userId`

## 2 auth — 5 refresh
- [docs/SellerProof API/2 auth/5 refresh/folder.bru](docs/SellerProof API/2 auth/5 refresh/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/2 auth/5 refresh/1 Refresh missing refreshToken.bru](docs/SellerProof API/2 auth/5 refresh/1 Refresh missing refreshToken.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/5 refresh/2 Refresh invalid token.bru](docs/SellerProof API/2 auth/5 refresh/2 Refresh invalid token.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/5 refresh/3 Refresh token expired.bru](docs/SellerProof API/2 auth/5 refresh/3 Refresh token expired.bru)
  - Variables used: `{{baseUrl}}`, `{{expiredRefreshToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/5 refresh/4 Refresh token success.bru](docs/SellerProof API/2 auth/5 refresh/4 Refresh token success.bru)
  - Variables used: `{{baseUrl}}`, `{{refreshToken}}`
  - Saves: [bru.setEnvVar()](docs/SellerProof API/2 auth/5 refresh/4 Refresh token success.bru:33) → `accessToken`; [bru.setEnvVar()](docs/SellerProof API/2 auth/5 refresh/4 Refresh token success.bru:34) → `refreshToken`
- [docs/SellerProof API/2 auth/5 refresh/5 Refresh token wrong format.bru](docs/SellerProof API/2 auth/5 refresh/5 Refresh token wrong format.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/5 refresh/6 Refresh token empty string.bru](docs/SellerProof API/2 auth/5 refresh/6 Refresh token empty string.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none

## 2 auth — 4 profile
- [docs/SellerProof API/2 auth/4 profile/folder.bru](docs/SellerProof API/2 auth/4 profile/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/2 auth/4 profile/1 Get profile without JWT token.bru](docs/SellerProof API/2 auth/4 profile/1 Get profile without JWT token.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/4 profile/5 Get profile with invalid JWT token.bru](docs/SellerProof API/2 auth/4 profile/5 Get profile with invalid JWT token.bru)
  - Variables used: `{{baseUrl}}` (explicit header uses a literal token string)
  - Saves: none
- [docs/SellerProof API/2 auth/4 profile/9 Get profile success with valid JWT.bru](docs/SellerProof API/2 auth/4 profile/9 Get profile success with valid JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/4 profile/10 Update profile success with valid JWT.bru](docs/SellerProof API/2 auth/4 profile/10 Update profile success with valid JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/4 profile/13 Update profile invalid JSON.bru](docs/SellerProof API/2 auth/4 profile/13 Update profile invalid JSON.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none

## 2 auth — switch-organization
- [docs/SellerProof API/2 auth/switch-organization/folder.bru](docs/SellerProof API/2 auth/switch-organization/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/2 auth/switch-organization/1 Switch organization success.bru](docs/SellerProof API/2 auth/switch-organization/1 Switch organization success.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testOrgId}}`
  - Saves: [bru.setEnvVar()](docs/SellerProof%20API/2%20auth/switch-organization/1%20Switch%20organization%20success.bru:36) → `accessToken`
- [docs/SellerProof API/2 auth/switch-organization/2 Switch organization without JWT token.bru](docs/SellerProof API/2 auth/switch-organization/2 Switch organization without JWT token.bru)
  - Variables used: `{{baseUrl}}`, `{{testOrgId}}`
  - Saves: none
- [docs/SellerProof API/2 auth/switch-organization/3 Switch organization with invalid JWT token.bru](docs/SellerProof API/2 auth/switch-organization/3 Switch organization with invalid JWT token.bru)
  - Variables used: `{{baseUrl}}`, `{{testOrgId}}` (Authorization uses a literal invalid token string)
  - Saves: none
- [docs/SellerProof API/2 auth/switch-organization/4 Switch organization missing org_id field.bru](docs/SellerProof API/2 auth/switch-organization/4 Switch organization missing org_id field.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/switch-organization/5 Switch organization with invalid org_id format.bru](docs/SellerProof API/2 auth/switch-organization/5 Switch organization with invalid org_id format.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/switch-organization/6 Switch organization user not member.bru](docs/SellerProof API/2 auth/switch-organization/6 Switch organization user not member.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/switch-organization/7 Switch organization inactive membership.bru](docs/SellerProof API/2 auth/switch-organization/7 Switch organization inactive membership.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{inactiveOrgId}}`
  - Saves: none
- [docs/SellerProof API/2 auth/switch-organization/8 Switch organization wrong HTTP method GET.bru](docs/SellerProof API/2 auth/switch-organization/8 Switch organization wrong HTTP method GET.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/switch-organization/9 Switch organization wrong HTTP method PUT.bru](docs/SellerProof API/2 auth/switch-organization/9 Switch organization wrong HTTP method PUT.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/switch-organization/10 Switch organization wrong HTTP method PATCH.bru](docs/SellerProof API/2 auth/switch-organization/10 Switch organization wrong HTTP method PATCH.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/2 auth/switch-organization/11 Switch organization wrong HTTP method DELETE.bru](docs/SellerProof API/2 auth/switch-organization/11 Switch organization wrong HTTP method DELETE.bru)
  - Variables used: `{{baseUrl}}` (by convention; file exists per index)
  - Saves: none

## 2 auth — 3 logout
- [docs/SellerProof API/2 auth/3 logout/folder.bru](docs/SellerProof API/2 auth/3 logout/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/2 auth/3 logout/1 Logout invalid request format.bru](docs/SellerProof API/2 auth/3 logout/1 Logout invalid request format.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/3 logout/2 Logout empty refresh token.bru](docs/SellerProof API/2 auth/3 logout/2 Logout empty refresh token.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/3 logout/3 Logout success.bru](docs/SellerProof API/2 auth/3 logout/3 Logout success.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{refreshToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/3 logout/4 Logout invalid JWT token.bru](docs/SellerProof API/2 auth/3 logout/4 Logout invalid JWT token.bru)
  - Variables used: `{{baseUrl}}`, `{{refreshToken}}` (Authorization uses a literal invalid token string)
  - Saves: none
- [docs/SellerProof API/2 auth/3 logout/5 Logout expired JWT token.bru](docs/SellerProof API/2 auth/3 logout/5 Logout expired JWT token.bru)
  - Variables used: `{{baseUrl}}`, `{{expiredAccessToken}}`, `{{refreshToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/3 logout/6 Logout malformed JWT token.bru](docs/SellerProof API/2 auth/3 logout/6 Logout malformed JWT token.bru)
  - Variables used: `{{baseUrl}}`, `{{refreshToken}}` (Authorization uses a literal malformed token string)
  - Saves: none
- [docs/SellerProof API/2 auth/3 logout/7 Logout missing JWT token.bru](docs/SellerProof API/2 auth/3 logout/7 Logout missing JWT token.bru)
  - Variables used: `{{baseUrl}}`, `{{refreshToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/3 logout/8 Logout invalid refresh token format.bru](docs/SellerProof API/2 auth/3 logout/8 Logout invalid refresh token format.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/3 logout/9 Logout expired refresh token.bru](docs/SellerProof API/2 auth/3 logout/9 Logout expired refresh token.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{expiredRefreshToken}}`
  - Saves: none
- [docs/SellerProof API/2 auth/3 logout/10 Logout non-existent refresh token.bru](docs/SellerProof API/2 auth/3 logout/10 Logout non-existent refresh token.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none

## 3 organization — accept
- [docs/SellerProof API/3 organization/accept/folder.bru](docs/SellerProof API/3 organization/accept/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/3 organization/accept/1 Accept invitation success with valid JWT.bru](docs/SellerProof API/3 organization/accept/1 Accept invitation success with valid JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{secondUserAccessToken}}`, `{{validInviteCode}}`
  - Saves: none
- [docs/SellerProof API/3 organization/accept/2 Accept invitation without JWT token.bru](docs/SellerProof API/3 organization/accept/2 Accept invitation without JWT token.bru)
  - Variables used: `{{baseUrl}}`
  - Saves: none
- [docs/SellerProof API/3 organization/accept/3 Accept invitation with invalid JWT token.bru](docs/SellerProof API/3 organization/accept/3 Accept invitation with invalid JWT token.bru)
  - Variables used: `{{baseUrl}}` (Authorization uses a literal invalid token string)
  - Saves: none
- [docs/SellerProof API/3 organization/accept/4 Accept invitation with expired JWT token.bru](docs/SellerProof API/3 organization/accept/4 Accept invitation with expired JWT token.bru)
  - Variables used: `{{baseUrl}}`, `{{expiredAccessToken}}`
  - Saves: none
- [docs/SellerProof API/3 organization/accept/5 Accept invitation with malformed JWT token.bru](docs/SellerProof API/3 organization/accept/5 Accept invitation with malformed JWT token.bru)
  - Variables used: `{{baseUrl}}` (Authorization uses a literal malformed token string)
  - Saves: none

## video — 1 upload
- [docs/SellerProof API/video/1 upload/folder.bru](docs/SellerProof API/video/1 upload/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/video/1 upload/initiate/2 Initiate upload success with valid JWT.bru](docs/SellerProof API/video/1 upload/initiate/2 Initiate upload success with valid JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/2%20Initiate%20upload%20success%20with%20valid%20JWT.bru:46) → `testVideoId`; [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/2%20Initiate%20upload%20success%20with%20valid%20JWT.bru:47) → `testUploadId`; [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/2%20Initiate%20upload%20success%20with%20valid%20JWT.bru:48) → `recommendedPartSizeMb`
- [docs/SellerProof API/video/1 upload/urls/2 Get upload URLs success with valid JWT.bru](docs/SellerProof API/video/1 upload/urls/2 Get upload URLs success with valid JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - Saves: loop over part_urls → [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/urls/2%20Get%20upload%20URLs%20success%20with%20valid%20JWT.bru:45) → `partUrl1`, `partUrl2`, `partUrl3`
- [docs/SellerProof API/video/1 upload/complete/2 Complete upload success with valid JWT.bru](docs/SellerProof API/video/1 upload/complete/2 Complete upload success with valid JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - Saves: none
- [docs/SellerProof API/video/1 upload/initiate/14 Initiate upload with non-ASCII filename.bru](docs/SellerProof API/video/1 upload/initiate/14 Initiate upload with non-ASCII filename.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/14%20Initiate%20upload%20with%20non-ASCII%20filename.bru:46) → `testVideoId`; [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/14%20Initiate%20upload%20with%20non-ASCII%20filename.bru:47) → `testUploadId`
- [docs/SellerProof API/video/1 upload/initiate/19 Initiate upload success with unicode file_name.bru](docs/SellerProof API/video/1 upload/initiate/19 Initiate upload success with unicode file_name.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{unicodeVideoName}}`
  - Saves: [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/19%20Initiate%20upload%20success%20with%20unicode%20file_name.bru:46) → `testUnicodeVideoId`; [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/19%20Initiate%20upload%20success%20with%20unicode%20file_name.bru:47) → `testUnicodeUploadId`; [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/19%20Initiate%20upload%20success%20with%20unicode%20file_name.bru:48) → `recommendedUnicodePartSizeMb`
- [docs/SellerProof API/video/1 upload/initiate/27 Initiate upload success with valid JWT copy.bru](docs/SellerProof API/video/1 upload/initiate/27 Initiate upload success with valid JWT copy.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/27%20Initiate%20upload%20success%20with%20valid%20JWT%20copy.bru:46) → `testSecVideoId`; [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/27%20Initiate%20upload%20success%20with%20valid%20JWT%20copy.bru:47) → `testSecUploadId`; [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/initiate/27%20Initiate%20upload%20success%20with%20valid%20JWT%20copy.bru:48) → `recommendedSecPartSizeMb`
- [docs/SellerProof API/video/1 upload/urls/22 Get upload URLs success with second user JWT.bru](docs/SellerProof API/video/1 upload/urls/22 Get upload URLs success with second user JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{secondUserAccessToken}}`, `{{secondUserVideoId}}`
  - Saves: loop → [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/urls/22%20Get%20upload%20URLs%20success%20with%20second%20user%20JWT.bru:45) → `secondUserPartUrl1`, `secondUserPartUrl2`, …
- [docs/SellerProof API/video/1 upload/urls/23 Get upload URLs success with valid JWT copy.bru](docs/SellerProof API/video/1 upload/urls/23 Get upload URLs success with valid JWT copy.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testSecVideoId}}`
  - Saves: loop → [bru.setEnvVar()](docs/SellerProof%20API/video/1%20upload/urls/23%20Get%20upload%20URLs%20success%20with%20valid%20JWT%20copy.bru:45) → `partUrl1`, `partUrl2`, …
- [docs/SellerProof API/video/1 upload/complete/25 Complete upload success with second user JWT.bru](docs/SellerProof API/video/1 upload/complete/25 Complete upload success with second user JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{secondUserAccessToken}}`, `{{secondUserVideoId}}`
  - Saves: none
- [docs/SellerProof API/video/1 upload/complete/24 Complete upload with Unicode video ID.bru](docs/SellerProof API/video/1 upload/complete/24 Complete upload with Unicode video ID.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testUnicodeVideoId}}`
  - Saves: none

## video — 2 publish
- [docs/SellerProof API/video/2 publish/folder.bru](docs/SellerProof API/video/2 publish/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/video/2 publish/1 Publish video success with valid JWT admin.bru](docs/SellerProof API/video/2 publish/1 Publish video success with valid JWT admin.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - Saves: [bru.setEnvVar()](docs/SellerProof%20API/video/2%20publish/1%20Publish%20video%20success%20with%20valid%20JWT%20admin.bru:37) → `publicVideoUrl`; [bru.setEnvVar()](docs/SellerProof%20API/video/2%20publish/1%20Publish%20video%20success%20with%20valid%20JWT%20admin.bru:38) → `publicShareToken`
- [docs/SellerProof API/video/2 publish/2 Publish video success with valid JWT manager.bru](docs/SellerProof API/video/2 publish/2 Publish video success with valid JWT manager.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - Saves: none
- [docs/SellerProof API/video/2 publish/24 Publish video already published.bru](docs/SellerProof API/video/2 publish/24 Publish video already published.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - Saves: none (commented optional save)

## video — 3 get
- [docs/SellerProof API/video/3 get/folder.bru](docs/SellerProof API/video/3 get/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/video/3 get/1 Get video success with valid JWT.bru](docs/SellerProof API/video/3 get/1 Get video success with valid JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - Saves: none
- [docs/SellerProof API/video/3 get/5 Get video another users video.bru](docs/SellerProof API/video/3 get/5 Get video another users video.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{secondUserVideoId}}`
  - Saves: none

## video — 4 public
- [docs/SellerProof API/video/4 public/folder.bru](docs/SellerProof API/video/4 public/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/video/4 public/1 Get public video success with valid token.bru](docs/SellerProof API/video/4 public/1 Get public video success with valid token.bru)
  - Variables used: `{{baseUrl}}`, `{{publicShareToken}}`
  - Saves: none
- [docs/SellerProof API/video/4 public/5 Get public video revoked access.bru](docs/SellerProof API/video/4 public/5 Get public video revoked access.bru)
  - Variables used: `{{baseUrl}}` (token is a literal string)
  - Saves: none

## video — 5 download
- [docs/SellerProof API/video/5 download/folder.bru](docs/SellerProof API/video/5 download/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/video/5 download/1 Download video success with valid JWT.bru](docs/SellerProof API/video/5 download/1 Download video success with valid JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - Saves: none

## video — 6 revoke
- [docs/SellerProof API/video/6 revoke/folder.bru](docs/SellerProof API/video/6 revoke/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/video/6 revoke/1 Revoke video success with admin JWT.bru](docs/SellerProof API/video/6 revoke/1 Revoke video success with admin JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - Saves: none
- [docs/SellerProof API/video/6 revoke/5 Revoke video not published.bru](docs/SellerProof API/video/6 revoke/5 Revoke video not published.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testSecVideoId}}`
  - Saves: none

## video — 7 delete
- [docs/SellerProof API/video/7 delete/folder.bru](docs/SellerProof API/video/7 delete/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/video/7 delete/1 Delete video success with valid JWT.bru](docs/SellerProof API/video/7 delete/1 Delete video success with valid JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - Saves: none

## video — 8 search
- [docs/SellerProof API/video/8 search/folder.bru](docs/SellerProof API/video/8 search/folder.bru)
  - Variables used: none
  - Saves: none
- [docs/SellerProof API/video/8 search/1 Search videos success with valid JWT.bru](docs/SellerProof API/video/8 search/1 Search videos success with valid JWT.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/video/8 search/2 Search videos with query parameter.bru](docs/SellerProof API/video/8 search/2 Search videos with query parameter.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/video/8 search/3 Search videos with pagination parameters.bru](docs/SellerProof API/video/8 search/3 Search videos with pagination parameters.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none
- [docs/SellerProof API/video/8 search/4 Search videos with all parameters.bru](docs/SellerProof API/video/8 search/4 Search videos with all parameters.bru)
  - Variables used: `{{baseUrl}}`, `{{accessToken}}`
  - Saves: none