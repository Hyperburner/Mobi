# Lahore Bridge Learning Club — Setup, Security, Migration & Verification Guide (V3)

## 1. What Is Included in This V3 Bundle (`bridge_community_portal_bundle.zip`)

| File | Purpose |
| :--- | :--- |
| `index.html` | **Production Web App (Cloudflare Pages)**: Connects exclusively to your live Supabase backend (`DEPLOYMENT_SUPABASE_CONFIG`). Ships **zero** assessment answer keys, **zero** `BackendGradingEngine` code, **zero** fictional demo records, and **zero** external BBO links. |
| `demo.html` | **Standalone Interactive Demo Sandbox & 16-Test Verification Runner**: Contains fictional club personas (`Amina Tariq`, `Bilal Kareem`, `Zara Siddiqui`), simulated durable accounts, Founding 100 allocation, Friends-Only Direct Messaging, and the in-browser 16-part automated test suite. |
| `schema.sql` | **Complete Fresh-Install PostgreSQL Schema (V1 + V2 + V3 + V3.1)**: Idempotent SQL script creating all tables, Row-Level Security (RLS) policies, indexes, triggers, audited curriculum seed data (`1E`, `1F`, and locked `1G`), and all `SECURITY DEFINER` RPCs. |
| `migration_v2_club_academy.sql` | **V1 → V2 Incremental Migration**: Upgrades a v1 database with automated deterministic grading, mistake queues, friendships, blocks, posts, and sessions. |
| `migration_v3_accounts_dm_founding100.sql` | **V2 → V3 Incremental Migration**: Fixes all 3 source-review concurrency/authorization findings and adds durable learner accounts (`members.auth_user_id`), legacy invitation progress linking (`learner_claim_or_register_account`), atomic Founding 100 allocation (`allocate_founding_membership_if_eligible`), Friends-Only Direct Messaging (`direct_messages`), and Study Groups (`study_groups`). |
| `migration_v3_1_email_verification_and_invitation_retirement.sql` | **Existing V3 → V3.1 Incremental Migration**: Reconciles `members.email_verified_at` strictly against `auth.users.email_confirmed_at` (removing the `now()` fallback), requires verified email for email-only profile linking and Founding 100 eligibility, revokes legacy bearer invitations when a durable account is linked, rejects bearer access and new invitation issuance for linked profiles, and requires authenticated account ownership for private messaging. |
| `IMPLEMENTATION_BACKLOG.md` | **Gap Analysis, Architecture & Multi-Phase Backlog**: Documents what is Working, Partial, and Missing across Learning, Community, and Playing, plus the architecture and verified pricing for Supabase, Cloudflare Durable Objects (4-human real-time bridge), and Android/iOS store releases. |
| `CONTENT_VALIDATION_REPORT.md` | **Curriculum Audit Report**: Documents every hand in `Lesson 1E.docx`, `Lesson 1F.docx`, `Lesson 1G.docx`, and `Answers Lesson 1E, 1F and 1G.docx`, explaining why 1E (6 core + 3 extra hands) and 1F (10 hands) are published while 12 defective/conflicting hands and Lesson 1G are withheld. |
| `first_six_hands.html` | **Standalone "Your First Six Bridge Hands" Experience**: Self-contained interactive introduction using the 6 verified hands from Lesson 1E. |
| `verify_v3_foundation.py` | **Automated Concurrency, Isolation & Multi-Session Browser Verification Script**: Runs real transactional concurrency tests (`sqlite3` with explicit row/advisory lock simulation + PL/pgSQL contract checks) and multi-session headless Chromium verification across `demo.html` and `index.html`. |
| `_headers`, `manifest.json`, `sw.js`, `icon-192.svg`, `icon-512.svg` | **Cloudflare Pages Security Headers & PWA Assets**: Enforces `Referrer-Policy: no-referrer`, frame-ancestors protection, and offline handbook caching. |

---

## 2. Summary of V3 Fixes & New Foundation Capabilities

### A. Fixes for All 3 Source-Review Findings
1. **Practice Hand Authorization & Readiness Gate (`public.learner_check_practice_hand`)**:
   - Before accessing `public.lesson_private_materials`, the function verifies that:
     1. The caller has an active assignment in `public.lesson_assignments` (`status <> 'Paused'`), raising `NOT_ASSIGNED` or `ASSIGNMENT_PAUSED` otherwise.
     2. The target lesson in `public.lessons` is published and validated (`is_draft = false` and `validation_status = 'validated'`), raising `LESSON_NOT_VALIDATED` otherwise.
2. **Explicit, Retry-Safe Session Join/Leave with Atomic Capacity Enforcement (`public.learner_manage_session`)**:
   - Uses explicit `'create'`, `'join'`, and `'leave'` actions.
   - On `'join'` and `'leave'`, the database acquires a row-level lock (`SELECT ps.id, ps.max_players FROM public.practice_sessions ps WHERE ps.id = p_session_id FOR UPDATE`) before checking existing membership or counting seated players (`max_players = 4`).
   - Retrying `'join'` when already seated returns `{ "status": "joined", "idempotent": true }` without error or duplicate rows; retrying `'leave'` when already unseated returns `{ "status": "left", "idempotent": true }`.
3. **Persistent Scoped `client_request_id` Deduplication & Row-Locked Attempt Numbering (`public.learner_submit_and_grade_lesson` & `public.learner_submit_work`)**:
   - Added `client_request_id text` to `public.submissions` with a partial unique index `UNIQUE (assignment_id, client_request_id) WHERE client_request_id IS NOT NULL`.
   - On the frontend, `getOrCreatePendingSubmissionRequestId` persists pending submission request IDs in `localStorage` (`bridge_pending_submission_reqs_v3`) scoped to `(authenticatedLearnerScope, lessonCode)` and the canonicalized submitted payload signature (`{ lessonCode, answers, questions }`).
   - If a network response is lost or the browser is refreshed before confirmation, retrying the same submission reuses the exact same `client_request_id`.
   - Changing any answer or question, switching to another learner account, or submitting an intentional new attempt after a confirmed submission automatically generates a fresh `client_request_id`. Pending state is cleared only after confirmed server success.

### B. Durable Cross-Device Learner Accounts, Authoritative Email Verification, Password Recovery & Legacy Invitation Retirement
- Learners can create a durable Supabase Auth account (email + password), sign in, or complete password recovery from any device via the **👤 Learner Account / Founding 100** modal.
- **Complete Password Recovery Flow**:
  - Requesting recovery calls `sb.auth.resetPasswordForEmail(email, { redirectTo: window.location.origin + window.location.pathname })`.
  - When the user returns via a recovery link (`#access_token=...&type=recovery`, `?token_hash=...&type=recovery`, `?code=...&type=recovery`, or the `PASSWORD_RECOVERY` auth state event), `processPasswordRecoveryUrl` verifies the recovery session, scrubs the URL bar, opens the account modal to **Password Recovery**, and displays the **Set New Password** form (`#learnerResetPasswordForm`).
  - Submitting the new password calls `sb.auth.updateUser({ password })`, displays confirmation, and retains the authenticated learner session (`auth:<user_id>`).
  - Invalid or expired recovery links (`#error=access_denied&error_code=otp_expired...` or rejected/missing recovery tokens) open the **Password Recovery** tab in request mode with an actionable error message so the learner can immediately request a fresh link.
- `public.learner_claim_or_register_account` reads `email_confirmed_at` directly from `auth.users` with **no** `now()` fallback, requires verified email for email-only profile linking (`EMAIL_NOT_VERIFIED`), and preserves organiser restrictions.
- When a learner links a durable account:
  - All active legacy bearer invitations in `public.learner_invitations` for that member are immediately revoked (`revoked_at = now()`).
  - `public.resolve_learner_identity` preserves authenticated access (`auth.uid()`) and rejects bearer token access to any profile with `auth_user_id IS NOT NULL` (`ACCOUNT_LINKED`).
  - `public.organiser_issue_invitation` prevents issuing new bearer invitations for linked profiles (`ACCOUNT_LINKED`).
  - The frontend retains the authenticated identity (`auth:<auth_user_id>`) rather than the retired invitation token.

### C. Atomic Founding 100 Lifetime Premium Allocation
- `public.allocate_founding_membership_if_eligible(p_member_id)` acquires transaction advisory lock `pg_advisory_xact_lock(77100)`, verifies that the member is an active non-organiser learner with a linked account whose email is confirmed in `auth.users.email_confirmed_at` (`email_verified_at IS NOT NULL`), and atomically assigns the next sequential `founder_number` (`1..100`) and `membership_tier = 'founding_100'`.
- Once 100 Founding memberships are allocated, subsequent accounts receive `membership_tier = 'standard'` (`reason: 'FOUNDING_100_FULL'`).

### D. Friends-Only 1-to-1 Direct Messaging & Study Groups
- `public.learner_send_direct_message`, `public.learner_get_direct_messages`, and `public.learner_report_direct_message` require authenticated account ownership (`auth.uid()` matching `members.auth_user_id`, revoked from `anon`) and allow 1-to-1 messages **only** when `public.member_friendships` has `status = 'accepted'` between sender and recipient and **zero** rows exist in `public.member_blocks` in either direction.
- `public.organiser_get_dashboard` queries **only** messages where `moderation_status = 'reported'`—non-reported private messages are never exposed to the organiser or any third party.

---

## 3. Step-by-Step Supabase & Cloudflare Pages Deployment

### Step 1: Apply the SQL Schema / Migration in Supabase
1. Open your [Supabase Dashboard](https://supabase.com/dashboard) → **SQL Editor**.
2. **Fresh project**: Paste and run the entire `schema.sql` file (includes V1 + V2 + V3 + V3.1).
3. **Existing V2 project**: Paste and run `migration_v3_accounts_dm_founding100.sql`.
4. **Existing V3 project**: Paste and run `migration_v3_1_email_verification_and_invitation_retirement.sql`.
5. Authorize your Organiser account by running:
   ```sql
   INSERT INTO public.organiser_users (user_id, email)
   SELECT id, email FROM auth.users WHERE email = 'YOUR_ORGANISER_EMAIL@example.com'
   ON CONFLICT (user_id) DO NOTHING;
   ```

### Step 2: Configure Required Supabase Auth Redirect URLs (Password Recovery & Email Verification)
Because `apiLearnerRecoverPassword` passes `redirectTo: window.location.origin + window.location.pathname` to `supabase.auth.resetPasswordForEmail(...)`, Supabase Auth requires your deployment URLs to be allowlisted:
1. Open [Supabase Dashboard](https://supabase.com/dashboard) → **Authentication** → **URL Configuration**.
2. Set **Site URL** to your production portal origin (for example, `https://lahore-bridge-club.pages.dev`).
3. Under **Redirect URLs**, add both the root path and `/index.html` for your production domain (and local test server if used):
   - `https://lahore-bridge-club.pages.dev/`
   - `https://lahore-bridge-club.pages.dev/index.html`
   - `http://localhost:8000/` and `http://localhost:8000/index.html` (optional for local browser testing)
4. Ensure **Enable Email Confirmations** is enabled under **Authentication → Providers → Email** so `auth.users.email_confirmed_at` is populated only after the user clicks their verification link.

### Step 3: Configure Public Supabase Credentials in `index.html`
1. Open `index.html` (or use the **Supabase Setup & Security** modal in the app to export a clean configured `index.html` from `CLEAN_IMMUTABLE_APP_TEMPLATE`) and set:
   ```javascript
   const DEPLOYMENT_SUPABASE_CONFIG = {
     url: 'https://YOUR-PROJECT-REF.supabase.co',
     anonKey: 'YOUR_PUBLIC_ANON_OR_PUBLISHABLE_KEY'
   };
   ```
2. **Security rule**: Never place your Supabase `service_role` secret key in `index.html`.

### Step 4: Deploy to Cloudflare Pages
1. Upload the bundle directory (`index.html`, `demo.html`, `first_six_hands.html`, `_headers`, `manifest.json`, `sw.js`, `icon-192.svg`, `icon-512.svg`) to [Cloudflare Pages](https://pages.cloudflare.com/).
2. Production learners and organisers use `/index.html` (or `/`); `/demo.html` remains available as an isolated training/testing sandbox.
