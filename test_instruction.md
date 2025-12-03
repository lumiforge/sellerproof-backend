# Bruno Tests Variable Map and Execution Guide

This document provides a comprehensive guide for running Bruno tests, including variable dependencies, execution sequence, and environment variable tracking.

## Environment Variables

### Predefined Variables (from environments/SellerProf.bru)
**Secret Variables (must be set before running tests):**
- `baseUrl` - API base URL
- `testEmail` - Primary test user email

**Predefined Variables:**
- `testEmailPassword` - Primary test user password
- `validVerificationCode` - Email verification code for primary user
- `expiredRefreshToken` - Expired refresh token for testing
- `refreshToken` - Initial refresh token
- `expiredAccessToken` - Expired access token for testing
- `testVideoId` - Initial test video ID
- `testUploadId` - Initial test upload ID
- `unicodeVideoName` - Unicode video name for testing
- `testUnicodeVideoId` - Unicode test video ID
- `testUnicodeUploadId` - Unicode test upload ID
- `recommendedUnicodePartSizeMb` - Unicode recommended part size
- `secondUserEmail` - Second test user email
- `secondUserPassword` - Second test user password
- `secondUserVerificationCode` - Verification code for second user
- `secondUserAccessToken` - Second user access token (initially empty)
- `secondUserRefreshToken` - Second user refresh token (initially empty)
- `secondUserVideoId` - Second user video ID
- `headerEtag1`, `headerEtag2`, `headerEtag3` - ETag headers
- `partUrl1`, `partUrl2`, `partUrl3` - Upload part URLs (initially empty)
- `testOrgId` - Test organization ID (initially empty)
- `secondUserOrgId` - Second user organization ID (initially empty)
- `validInvitationId` - Valid invitation ID (initially empty)
- `userId` - Primary user ID (initially empty)
- `secondUserId` - Second user ID (initially empty)
- `publicVideoUrl` - Public video URL (initially empty)
- `testOrganizationName` - Test organization name
- `testFullName` - Test user full name
- `secondUserFullName` - Second user full name
- `secondUserOrganizationName` - Second user organization name
- `invalidAccessToken` - Invalid access token for testing
- `invalidRefreshToken` - Invalid refresh token for testing
- `recommendedPartSizeMb` - Recommended part size (initially empty)
- `testSecVideoId` - Secondary test video ID (initially empty)
- `testSecUploadId` - Secondary test upload ID (initially empty)

## Recommended Test Execution Sequence

### Phase 1: Health Checks
**Folder:** `1 health`
- **Purpose:** Verify API is accessible
- **Variables used:** `baseUrl`
- **Variables saved:** None
- **Execution order:** Any order
- **Files:**
  - `Health check.bru` - GET health check
  - `Health check POST.bru` - POST health check
  - `Health check PUT.bru` - PUT health check
  - `Health check PATCH.bru` - PATCH health check
  - `Health check DELETE.bru` - DELETE health check
  - `Health check 404.bru` - 404 error test

### Phase 2: User Registration
**Folder:** `2 auth/1 register`
- **Purpose:** Register test users
- **Variables used:** `baseUrl`, `testEmail`, `testEmailPassword`, `secondUserEmail`, `secondUserPassword`
- **Variables saved:** None
- **Execution order:** 
  1. `1 Register success.bru` - Register primary user
  2. `2 Register second user success.bru` - Register second user
  3. Other registration tests (error cases)
- **Key files:**
  - `1 Register success.bru` - Uses `{{baseUrl}}`, `{{testEmail}}`, `{{testEmailPassword}}`
  - `2 Register second user success.bru` - Uses `{{baseUrl}}`, `{{secondUserEmail}}`, `{{secondUserPassword}}`

### Phase 3: Email Verification and Login
**Folder:** `2 auth/2 login`
- **Purpose:** Verify emails and login to get tokens
- **Variables used:** `baseUrl`, `testEmail`, `testEmailPassword`, `validVerificationCode`, `secondUserEmail`, `secondUserVerificationCode`
- **Variables saved:** `accessToken`, `refreshToken`, `testOrgId`, `userId`, `secondUserAccessToken`, `secondUserRefreshToken`, `secondUserOrgId`, `secondUserId`
- **Execution order:**
  1. `3 Verify Email correct.bru` - Verify primary user email
  2. `9 User login success verified.bru` - Login primary user (saves tokens)
  3. `14 Verify second user email correct.bru` - Verify second user email
  4. `15 Second user login success verified.bru` - Login second user (saves tokens)
  5. Other login tests (error cases)
- **Key files:**
  - `3 Verify Email correct.bru` - Uses `{{baseUrl}}`, `{{testEmail}}`, `{{validVerificationCode}}`
  - `9 User login success verified.bru` - Uses `{{baseUrl}}`, `{{testEmail}}`, `{{testEmailPassword}}` → Saves: `accessToken`, `refreshToken`, `testOrgId`, `userId`
  - `15 Second user login success verified.bru` - Uses `{{baseUrl}}`, `{{secondUserEmail}}`, `{{secondUserPassword}}` → Saves: `secondUserAccessToken`, `secondUserRefreshToken`, `secondUserOrgId`, `secondUserId`

### Phase 4: Token Refresh
**Folder:** `2 auth/5 refresh`
- **Purpose:** Test token refresh functionality
- **Variables used:** `baseUrl`, `refreshToken`, `expiredRefreshToken`
- **Variables saved:** `accessToken`, `refreshToken` (updated)
- **Execution order:** After successful login
- **Key files:**
  - `4 Refresh token success.bru` - Uses `{{baseUrl}}`, `{{refreshToken}}` → Saves: `accessToken`, `refreshToken`
  - `18 Refresh extra fields.bru` - Uses `{{baseUrl}}`, `{{refreshToken}}` → Saves: `accessToken`, `refreshToken`

### Phase 5: Organization Management
**Folder:** `3 organization`
- **Purpose:** Create and manage organizations
- **Variables used:** `baseUrl`, `accessToken`, `testOrgId`, `secondUserAccessToken`
- **Variables saved:** `validInvitationId`, `validInviteCode`
- **Execution order:** After user login
- **Subfolders:**
  - `create/` - Create organization tests
  - `invitations/` - Get invitations tests
  - `invitations/delete/` - Delete invitation tests
  - `accept/` - Accept invitation tests
- **Key files:**
  - `invite/1 Invite user success with valid JWT admin.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testOrgId}}` → Saves: `validInvitationId`, `validInviteCode`
  - `accept/1 Accept invitation success with valid JWT.bru` - Uses `{{baseUrl}}`, `{{secondUserAccessToken}}`, `{{validInviteCode}}`

### Phase 6: Organization Switching
**Folder:** `2 auth/switch-organization`
- **Purpose:** Test organization switching
- **Variables used:** `baseUrl`, `accessToken`, `testOrgId`
- **Variables saved:** `accessToken` (updated)
- **Execution order:** After organization creation
- **Key files:**
  - `1 Switch organization success.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testOrgId}}` → Saves: `accessToken`

### Phase 7: Video Upload Workflow
**Folder:** `video/1 upload`
- **Purpose:** Complete video upload workflow
- **Variables used:** `baseUrl`, `accessToken`, `secondUserAccessToken`, `testVideoId`, `secondUserVideoId`, `testSecVideoId`, `testUnicodeVideoId`
- **Variables saved:** `testVideoId`, `testUploadId`, `recommendedPartSizeMb`, `testUnicodeVideoId`, `testUnicodeUploadId`, `recommendedUnicodePartSizeMb`, `testSecVideoId`, `testSecUploadId`, `recommendedSecPartSizeMb`, `partUrl1`, `partUrl2`, `partUrl3`, `secondUserPartUrl1`, `secondUserPartUrl2`, `secondUserPartUrl3`
- **Execution order:** Sequential within each subfolder
- **Subfolders:**
  - `initiate/` - Start upload process
  - `urls/` - Get upload URLs
  - `complete/` - Complete upload
- **Key files:**
  - `initiate/2 Initiate upload success with valid JWT.bru` - Uses `{{baseUrl}}`, `{{accessToken}}` → Saves: `testVideoId`, `testUploadId`, `recommendedPartSizeMb`
  - `initiate/14 Initiate upload with non-ASCII filename.bru` - Uses `{{baseUrl}}`, `{{accessToken}}` → Saves: `testVideoId`, `testUploadId`
  - `initiate/19 Initiate upload success with unicode file_name.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{unicodeVideoName}}` → Saves: `testUnicodeVideoId`, `testUnicodeUploadId`, `recommendedUnicodePartSizeMb`
  - `initiate/27 Initiate upload success with valid JWT copy.bru` - Uses `{{baseUrl}}`, `{{accessToken}}` → Saves: `testSecVideoId`, `testSecUploadId`, `recommendedSecPartSizeMb`
  - `urls/2 Get upload URLs success with valid JWT.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}` → Saves: `partUrl1`, `partUrl2`, `partUrl3`
  - `urls/22 Get upload URLs success with second user JWT.bru` - Uses `{{baseUrl}}`, `{{secondUserAccessToken}}`, `{{secondUserVideoId}}` → Saves: `secondUserPartUrl1`, `secondUserPartUrl2`, `secondUserPartUrl3`
  - `urls/23 Get upload URLs success with valid JWT copy.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testSecVideoId}}` → Saves: `partUrl1`, `partUrl2`, `partUrl3`
  - `complete/2 Complete upload success with valid JWT.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - `complete/24 Complete upload with Unicode video ID.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testUnicodeVideoId}}`
  - `complete/25 Complete upload success with second user JWT.bru` - Uses `{{baseUrl}}`, `{{secondUserAccessToken}}`, `{{secondUserVideoId}}`

### Phase 8: Video Publishing
**Folder:** `video/2 publish`
- **Purpose:** Publish videos for public access
- **Variables used:** `baseUrl`, `accessToken`, `testVideoId`
- **Variables saved:** `publicVideoUrl`, `publicShareToken`
- **Execution order:** After successful upload completion
- **Key files:**
  - `1 Publish video success with valid JWT admin.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}` → Saves: `publicVideoUrl`, `publicShareToken`
  - `2 Publish video success with valid JWT manager.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - `24 Publish video already published.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`

### Phase 9: Video Access and Management
**Folders:** `video/3 get`, `video/4 public`, `video/5 download`, `video/6 revoke`, `video/7 delete`, `video/8 search`
- **Purpose:** Test video operations
- **Variables used:** `baseUrl`, `accessToken`, `testVideoId`, `secondUserVideoId`, `testUnicodeVideoId`, `testSecVideoId`, `publicShareToken`
- **Variables saved:** None
- **Execution order:** After video publishing
- **Key files:**
  - `3 get/1 Get video success with valid JWT.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - `3 get/5 Get video another users video.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{secondUserVideoId}}`
  - `4 public/1 Get public video success with valid token.bru` - Uses `{{baseUrl}}`, `{{publicShareToken}}`
  - `5 download/1 Download video success with valid JWT.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - `6 revoke/1 Revoke video success with admin JWT.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - `6 revoke/5 Revoke video not published.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testSecVideoId}}`
  - `7 delete/1 Delete video success with valid JWT.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{testVideoId}}`
  - `8 search/1 Search videos success with valid JWT.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`

### Phase 10: Profile Management
**Folder:** `2 auth/4 profile`
- **Purpose:** Test user profile operations
- **Variables used:** `baseUrl`, `accessToken`
- **Variables saved:** None
- **Execution order:** After user login
- **Key files:**
  - `9 Get profile success with valid JWT.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`
  - `10 Update profile success with valid JWT.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`

### Phase 11: Logout
**Folder:** `2 auth/3 logout`
- **Purpose:** Test logout functionality
- **Variables used:** `baseUrl`, `accessToken`, `refreshToken`, `expiredAccessToken`, `expiredRefreshToken`
- **Variables saved:** None
- **Execution order:** After all other tests
- **Key files:**
  - `3 Logout success.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{refreshToken}}`
  - `5 Logout expired JWT token.bru` - Uses `{{baseUrl}}`, `{{expiredAccessToken}}`, `{{refreshToken}}`
  - `9 Logout expired refresh token.bru` - Uses `{{baseUrl}}`, `{{accessToken}}`, `{{expiredRefreshToken}}`

## Variable Dependency Flow

### Primary User Flow:
1. **Registration:** Uses `testEmail`, `testEmailPassword`
2. **Verification:** Uses `validVerificationCode`
3. **Login:** Saves `accessToken`, `refreshToken`, `testOrgId`, `userId`
4. **Token Refresh:** Updates `accessToken`, `refreshToken`
5. **Organization Switch:** Updates `accessToken`
6. **Video Operations:** Uses `accessToken`, saves video-related variables
7. **Profile Management:** Uses `accessToken`
8. **Logout:** Uses `accessToken`, `refreshToken`

### Second User Flow:
1. **Registration:** Uses `secondUserEmail`, `secondUserPassword`
2. **Verification:** Uses `secondUserVerificationCode`
3. **Login:** Saves `secondUserAccessToken`, `secondUserRefreshToken`, `secondUserOrgId`, `secondUserId`
4. **Organization Operations:** Uses `secondUserAccessToken`
5. **Video Operations:** Uses `secondUserAccessToken`, saves second user video variables

## Critical Dependencies

### Must Complete Before:
- **Login tests** → Registration must be completed first
- **Token refresh tests** → Login must be completed first
- **Organization tests** → Login must be completed first
- **Video upload tests** → Login must be completed first
- **Video publish tests** → Upload must be completed first
- **Video access tests** → Publish must be completed first
- **Logout tests** → All other tests should be completed first

### Variable Updates:
- `accessToken` and `refreshToken` are updated during login and refresh operations
- Video IDs are generated during upload initiation
- Public tokens are generated during video publishing
- Organization IDs are generated during organization creation

## Running Tests

### Prerequisites:
1. Set `baseUrl` and `testEmail` as secret variables in Bruno environment
2. Ensure all predefined variables are properly configured
3. Run tests in the recommended sequence

### Full Test Suite Execution:
1. Run all health check tests
2. Run registration tests in order
3. Run email verification and login tests in order
4. Run token refresh tests
5. Run organization management tests
6. Run organization switching tests
7. Run video upload workflow tests sequentially
8. Run video publishing tests
9. Run video access and management tests
10. Run profile management tests
11. Run logout tests last

### Individual Test Execution:
When running individual tests, ensure all required variables are available in the environment. Check the "Variables used" section for each test to verify prerequisites.