# Lahore Bridge Learning Club — Architecture, Gap Audit & Full-Scope Implementation Backlog

## 1. Current Build Status Audit (Working vs. Partial vs. Missing)

| Product Area / Requirement | Status in Current V3 Bundle | Honest Technical Detail & Verification Scope |
| :--- | :--- | :--- |
| **Durable Cross-Device Learner Accounts (`auth.users` + `public.members`)** | **Working (Completed in V3)** | `public.members.auth_user_id` links directly to `auth.users(id)`. Supports cross-device email/password sign-up, sign-in, and `resetPasswordForEmail` recovery via `public.learner_claim_or_register_account` and `public.resolve_learner_identity`. |
| **Legacy Invitation-Token Progress Linking** | **Working (Completed in V3)** | Existing learners with SHA-256 invitation tokens can link their existing `public.members` row to a durable account in 1 click without losing any assignments, submissions, feedback, mistake-queue items, friendships, or session RSVPs. |
| **Practice Hand Authorization & Readiness Gate (Review Fix #1)** | **Working (Completed in V3)** | `public.learner_check_practice_hand` verifies that the learner has an active (non-`'Paused'`) assignment for `p_lesson_code` **and** that the lesson is published (`is_draft = false`, `validation_status = 'validated'`) before reading `public.lesson_private_materials`. |
| **Explicit, Retry-Safe Session Join/Leave & Atomic Capacity (Review Fix #2)** | **Working (Completed in V3)** | Replaced `toggle_rsvp` with explicit `'create'`, `'join'`, and `'leave'` actions in `public.learner_manage_session`. Acquires `SELECT ... FROM public.practice_sessions WHERE id = p_session_id FOR UPDATE` before counting seated players (`max_players = 4`) and makes retries idempotent. |
| **Durable `client_request_id` & Row-Locked Attempt Versioning (Review Fix #3)** | **Working (Completed in V3)** | Added `client_request_id text` (with `UNIQUE (assignment_id, client_request_id)`) to `public.submissions`. `public.learner_submit_and_grade_lesson` and `public.learner_submit_work` lock `public.lesson_assignments FOR UPDATE`, deduplicate retries by `client_request_id`, and allocate `version_number` atomically. |
| **Atomic Founding 100 Lifetime Premium Allocation** | **Working (Completed in V3)** | `public.allocate_founding_membership_if_eligible` uses transaction advisory lock `pg_advisory_xact_lock(77100)` to assign sequential `founder_number` (`1..100`) to verified accounts (`auth_user_id IS NOT NULL` and `email_verified_at IS NOT NULL`). Tested under 105 concurrent claims (exactly 100 allocated, `#101–#105` receive `'standard'`). Benefits are configurable in `public.club_settings.founding_100_benefits_json` with zero payment collection. |
| **Friends-Only 1-to-1 Direct Messaging & Study Groups** | **Working (Completed in V3)** | `public.direct_messages` enforces accepted friendship (`status = 'accepted'`) and mutual block checks (`public.member_blocks`) server-side in `public.learner_send_direct_message` and `public.learner_get_direct_messages`. Non-reported private DMs are never exposed to other learners or in `public.organiser_get_dashboard()`. Includes `public.study_groups`. |
| **Online & Printable Beginner Guides (`Bridge Foundations` & `Dennis's Method`) + Printable Practice Sheet** | **Working (Completed in V3)** | Generated from one canonical reviewed source (`BEGINNER_HANDBOOK_CHAPTERS` & `CANONICAL_RULES_CARDS`), distinguishing universal Laws of Contract Bridge from Dennis's 5-Card Major / 5-3-1 agreements. Includes interactive exercise jump-links and downloadable printable HTML/PDF editions plus a personalised printable Practice Collection. |
| **Zero External BBO Competitor Links** | **Working (Completed in V3)** | Removed all `Bridge Base Online` / `bridgebase.com` links and text from `index.html`, `demo.html`, and SQL defaults. |
| **Production vs. Demo Build Separation** | **Working (Completed in V3)** | `index.html` ships zero assessment answer keys and zero `BackendGradingEngine` logic. All fictional personas and client-side grading simulation are isolated in `demo.html`. |
| **52-Card Play Table (Single-Player Guided & Bot vs. 4-Human Multiplayer)** | **Partial (Single-Player Guided & Bot Complete; 4-Human Real-Time Multiplayer Missing)** | 3 mathematically verified 52-card deals with strict follow-suit enforcement, trump/NT trick resolution, and scripted West/East defenders work today. Real-time 4-human network tables with hidden hands, live bidding clock, and reconnect handling are **not yet built** (Backlog Epic 1). |
| **Replayable Completed Hand Sharing to Community Feed** | **Partial (Data Schema & Feed Ready; 4-Human Hand Replay Widget Missing)** | Community posts support lesson/deal discussion today; full trick-by-trick interactive hand-replay cards from completed 4-human deals are scheduled in Backlog Epic 2. |
| **Mobile Apps (PWA vs. Native Android & iOS Store Apps)** | **Partial (Installable PWA Complete; Native Android `.aab` & iOS `.ipa` Missing)** | `manifest.json` + `sw.js` provide an interim installable PWA. Native Android and iOS builds sharing the same Supabase + WebSocket backend are scheduled in Backlog Epic 3. |
| **Lesson 1G & Withheld Source Hands (`1E` Hands 7/9/12, `1F` Hands 8/12)** | **Partial (Audited & Withheld Pending Author Confirmation)** | Lesson `1E` (6 core + 3 extra hands) and Lesson `1F` (10 hands) are validated and active. Lesson `1G` remains locked (`validation_status = 'awaiting_source_resolution'`) until Dennis resolves the 7 documented source anomalies. |

---

## 2. Chosen Full-Scope Architecture & Verified External Service Pricing

### A. Unified Backend, Accounts & Data Layer — **Supabase (PostgreSQL + Auth + RLS + RPCs)**
- **Role**: Single source of truth across Web, Android, and iOS for `auth.users`, `public.members`, `Founding 100` lifetime memberships (`founder_number 1..100`), curriculum & deterministic grading (`learner_submit_and_grade_lesson`), mistake queues, friendships, blocks, `direct_messages`, `study_groups`, and completed deal histories.
- **Verified Pricing**:
  - **Free Plan**: `$0 / month` (includes 50,000 Monthly Active Users, 500 MB PostgreSQL database, 5 GB egress; paused after 7 days of inactivity) — sufficient for initial development and pilot testing.
  - **Pro Plan**: `$25 / month` base (includes 100,000 MAUs, 8 GB database, 250 GB egress, daily automated backups, zero auto-pausing) — recommended for production launch of the 100-member club.

### B. Real-Time 4-Human Bridge Table Engine — **Cloudflare Pages + Cloudflare Durable Objects (WebSockets)**
- **Why Durable Objects over Client-Side Peer Broadcast**:
  - In a real 4-human bridge game, **no player client may ever receive the other three players' hidden 13-card holdings** over the network (and Dummy's hand must remain hidden until the opening lead is played).
  - Each active 4-player table maps to one single-threaded **Cloudflare Durable Object** instance (`BridgeTableRoomDO`) with WebSocket Hibernation and embedded SQLite state storage:
    1. **Authentication**: On WebSocket upgrade, the Durable Object verifies the player's Supabase Auth JWT (or signed table seat ticket) and maps `member_id` to North, East, South, or West.
    2. **Cryptographic 52-Card Deal & Hidden-Hand Isolation**: Generates a CSPRNG 52-card permutation (4 × 13 cards), persists the full deal inside the Durable Object's private storage, and transmits to each seat **only their own 13 cards** (revealing Dummy's remaining cards to all 4 seats only after the opening lead is legally played).
    3. **Authoritative Auction State Machine**: Enforces clockwise turn order starting from Dealer, validates legal calls (`Pass`, `1♣`–`7NT`, `X`, `XX`), detects 3 consecutive passes (or 4 initial passes), and determines Declarer, Dummy, Contract, and Opening Leader.
    4. **Authoritative Trick-Play State Machine**: Enforces clockwise play (with Declarer playing both Declarer and Dummy cards), validates mandatory follow-suit against the server's private hand state, resolves each of the 13 tricks, and computes Duplicate / Rubber bridge scoring.
    5. **Disconnect Grace Window & Bot Substitution**: Tracks seat heartbeats; if a player disconnects, holds the seat for a 60-second grace window and restores their exact state upon reconnect (or allows table host to substitute a deterministic bot seat).
    6. **Post-Deal Persistence & Replayable Sharing**: Upon Trick 13 completion, writes the full deal record (all 4 hands, auction sequence, 52 played cards in order, contract, and score) to Supabase (`public.completed_bridge_deals`) so players can review or share the deal as a replayable discussion post.
- **Verified Pricing**:
  - **Cloudflare Pages**: `$0 / month` for static frontend hosting and unlimited bandwidth.
  - **Cloudflare Workers Paid Plan (includes Durable Objects)**: `$5 / month` minimum (includes 10 million Worker requests, 1 million Durable Object requests, and 400,000 GB-s duration per month — easily supporting 100+ club members and dozens of concurrent 4-player tables).

### C. Native Android & iOS Mobile Apps — **Capacitor / React Native Shared TypeScript Client**
- **Architecture**: Shared TypeScript API/WebSocket client consuming the exact same Supabase RPCs (`learner_get_portal`, `learner_submit_and_grade_lesson`, `learner_send_direct_message`, etc.) and Cloudflare Durable Object WebSocket protocol, packaged into native Android (`.aab` for Google Play) and iOS (`.ipa` for Apple App Store) builds with native push notifications (FCM / APNs) and Universal Links / App Links for password recovery and table invites.
- **Verified Store Account Pricing**:
  - **Google Play Console**: `$25 USD` one-time developer registration fee.
  - **Apple Developer Program**: `$99 USD / year` annual membership fee.

---

## 3. Prioritised Multi-Phase Implementation Backlog

### Epic 1: In-House 4-Human Real-Time Multiplayer Bridge Engine (Next Build Milestone)
- [ ] **1.1 (`schema_v4_multiplayer_deals.sql`)**: Create `public.live_bridge_tables` (table lobby, seat assignments N/E/S/W, status, ruleset) and `public.completed_bridge_deals` (deal_id, board_number, dealer, vulnerability, hands_json, auction_json, tricks_json, contract, declarer, ns_tricks, score_ns) with RLS and `SECURITY DEFINER` RPCs.
- [ ] **1.2 (`cloudflare-worker/BridgeTableRoomDO.ts`)**: Implement the Cloudflare Durable Object WebSocket state machine enforcing hidden-card isolation (each WebSocket receives only its own seat's cards + Dummy after opening lead), clockwise auction validation, mandatory follow-suit checking, 13-trick resolution, and 60s reconnect grace periods.
- [ ] **1.3 (Frontend Lobby & Live Table UI)**: Connect the **Play** tab to the live WebSocket table room so 4 seated club members can bid and play a full 52-card deal together in real time, or fill empty seats with club bots.
- [ ] **1.4 (Load & Concurrency Verification)**: Run automated 4-client WebSocket tests (verifying hidden-card non-leakage in network frames, out-of-turn rejection, illegal revoke rejection, and mid-trick disconnect/reconnect recovery) before claiming multi-table support.

### Epic 2: Replayable Completed Hand Sharing & Curriculum Completion
- [ ] **2.1 (Interactive Hand Replay Widget)**: Add a `shared_deal_id` foreign key to `public.community_posts` and build an interactive trick-by-trick replay viewer (`◀ Prev Card | Next Card ▶`) inside community discussion posts.
- [ ] **2.2 (Lesson 1G & Withheld Hands Resolution)**: Once Dennis confirms the intended holdings/answers for the 7 flagged hands in `Lesson 1G.docx` (and the withheld hands in `1E` and `1F`), populate `public.lessons` (`code = '1G'`, `validation_status = 'validated'`, `is_draft = false`) and `public.lesson_private_materials` to enable automatic `1F → 1G` unlocking.

### Epic 3: Native Android & iOS App Packaging & Store Release
- [ ] **3.1 (Mobile Packaging & Deep Links)**: Initialize the Capacitor / React Native mobile wrapper around the shared club client, configure `assetlinks.json` (Android App Links) and `apple-app-site-association` (iOS Universal Links) for account verification and password reset redirects.
- [ ] **3.2 (Push Notifications)**: Wire Supabase Database Webhooks / Edge Functions to Firebase Cloud Messaging (Android) and APNs (iOS) for friend requests, direct messages, and 4-player table seat readiness alerts.
- [ ] **3.3 (Store Submission Artifacts)**: Produce signed Android `.aab` and iOS `.ipa` builds, privacy policy disclosures (no public email exposure, user blocking & reporting), and store screenshots.
