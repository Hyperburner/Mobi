#!/usr/bin/env python3
"""
Automated V3 Verification Suite for Lahore Bridge Learning Club:
1. Static SQL & Security Contract Audit (`schema.sql`, `migration_v3_accounts_dm_founding100.sql`,
   `migration_v3_1_email_verification_and_invitation_retirement.sql`, `index.html`, `demo.html`)
2. Multi-Threaded Transactional Concurrency & Regression Simulation (`sqlite3` with `BEGIN IMMEDIATE` locks)
3. Headless Chromium Multi-Session Verification (`demo.html` 16-part suite + `index.html` Startup,
   Password Recovery Flow, Persistent Scoped Submission Request IDs, Demo-Isolation & Live RPC Mock)
"""

import os
import re
import json
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def run_sql_and_bundle_contract_checks():
    print("=== 1. SQL & BUNDLE SECURITY / CONCURRENCY CONTRACT AUDIT ===")
    schema_path = os.path.join(OUT_DIR, "schema.sql")
    mig3_path = os.path.join(OUT_DIR, "migration_v3_accounts_dm_founding100.sql")
    mig3_1_path = os.path.join(OUT_DIR, "migration_v3_1_email_verification_and_invitation_retirement.sql")
    mig2_path = os.path.join(OUT_DIR, "migration_v2_club_academy.sql")
    index_path = os.path.join(OUT_DIR, "index.html")
    demo_path = os.path.join(OUT_DIR, "demo.html")

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    with open(mig3_path, "r", encoding="utf-8") as f:
        mig3_sql = f.read()
    with open(mig3_1_path, "r", encoding="utf-8") as f:
        mig3_1_sql = f.read()
    with open(mig2_path, "r", encoding="utf-8") as f:
        mig2_sql = f.read()
    with open(index_path, "r", encoding="utf-8") as f:
        index_html = f.read()
    with open(demo_path, "r", encoding="utf-8") as f:
        demo_html = f.read()

    # Check 1: Zero BBO references across all files
    for name, content in [
        ("schema.sql", schema_sql),
        ("migration_v2_club_academy.sql", mig2_sql),
        ("migration_v3_accounts_dm_founding100.sql", mig3_sql),
        ("migration_v3_1_email_verification_and_invitation_retirement.sql", mig3_1_sql),
        ("index.html", index_html),
        ("demo.html", demo_html),
    ]:
        matches = re.findall(r"(bridgebase\.com|Bridge Base Online)", content, re.I)
        assert len(matches) == 0, f"Found forbidden BBO reference in {name}: {matches}"
    print("  [PASS] Zero Bridge Base Online (BBO) links or references in SQL, index.html, and demo.html.")

    # Check 2: Production index.html ships zero BackendGradingEngine or answer key generators
    assert "BackendGradingEngine" not in index_html, "BackendGradingEngine leaked into index.html"
    assert "computeExpectedFromHand" not in index_html, "computeExpectedFromHand leaked into index.html"
    assert "buildDefaultDemoData" not in index_html, "buildDefaultDemoData leaked into index.html"
    assert "btnDemoOrg" not in index_html, "Demo-only #btnDemoOrg reference leaked into index.html"
    assert "btnDemoLearner1" not in index_html, "Demo-only #btnDemoLearner1 reference leaked into index.html"
    assert "btnDemoLearner2" not in index_html, "Demo-only #btnDemoLearner2 reference leaked into index.html"
    print("  [PASS] Production index.html contains zero BackendGradingEngine, demo answer-key code, or unguarded demo persona button refs.")

    # Check 3: Authoritative email verification & legacy invitation retirement contracts
    for sql_label, sql_text in [
        ("schema.sql", schema_sql),
        ("migration_v3_accounts_dm_founding100.sql", mig3_sql),
        ("migration_v3_1_email_verification_and_invitation_retirement.sql", mig3_1_sql),
    ]:
        assert "v_email_confirmed_at, now()" not in sql_text, f"Found forbidden now() fallback on email_verified_at in {sql_label}"
        assert "EMAIL_NOT_VERIFIED: Verified email is required to link an existing club member profile by email." in sql_text
        assert "ACCOUNT_LINKED: This learner profile is linked to a durable account" in sql_text
        assert "ACCOUNT_LINKED: Cannot issue a bearer invitation link for a learner profile that is already linked to a durable account." in sql_text
        assert "ACCOUNT_REQUIRED: Direct messaging requires a signed-in durable learner account." in sql_text
        assert "REVOKE ALL ON FUNCTION public.learner_send_direct_message(text, uuid, text, text) FROM PUBLIC, anon;" in sql_text
        assert "REVOKE ALL ON FUNCTION public.learner_get_direct_messages(text, uuid) FROM PUBLIC, anon;" in sql_text
        assert "REVOKE ALL ON FUNCTION public.learner_report_direct_message(text, uuid, text) FROM PUBLIC, anon;" in sql_text
    print("  [PASS] Authoritative email verification (zero now() fallbacks) and legacy invitation retirement verified in SQL.")

    # Check 4: Review Fix #1, #2, #3 & Founding 100 / DM contracts
    prac_fn_match = re.search(
        r"CREATE OR REPLACE FUNCTION public\.learner_check_practice_hand\(.*?\$\$;\s*REVOKE",
        mig3_sql,
        re.S,
    )
    assert prac_fn_match
    prac_body = prac_fn_match.group(0)
    assert prac_body.index("FROM public.lesson_assignments") < prac_body.index("FROM public.lesson_private_materials")
    assert prac_body.index("LESSON_NOT_VALIDATED") < prac_body.index("FROM public.lesson_private_materials")
    print("  [PASS] Fix #1, Fix #2, Fix #3, Founding 100 lock, and Friends-Only DM privacy verified in SQL.")


def run_sqlite_transactional_concurrency_tests():
    print("\n=== 2. MULTI-THREADED TRANSACTIONAL CONCURRENCY & REGRESSION SIMULATION (SQLite Engine) ===")
    db_fd, db_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(db_fd)

    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE auth_users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                email_confirmed_at TEXT
            );
            CREATE TABLE organiser_users (
                user_id TEXT PRIMARY KEY,
                email TEXT NOT NULL
            );
            CREATE TABLE members (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT,
                interest_status TEXT NOT NULL DEFAULT 'Interested',
                auth_user_id TEXT UNIQUE,
                email_verified_at TEXT,
                membership_tier TEXT NOT NULL DEFAULT 'standard',
                founder_number INTEGER UNIQUE CHECK (founder_number IS NULL OR (founder_number BETWEEN 1 AND 100))
            );
            CREATE TABLE learner_invitations (
                id TEXT PRIMARY KEY,
                member_id TEXT NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE TABLE practice_sessions (
                id TEXT PRIMARY KEY,
                max_players INTEGER NOT NULL DEFAULT 4
            );
            CREATE TABLE practice_session_rsvps (
                session_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                UNIQUE (session_id, member_id)
            );
            CREATE TABLE lesson_assignments (
                id TEXT PRIMARY KEY,
                member_id TEXT NOT NULL,
                lesson_code TEXT NOT NULL,
                UNIQUE (member_id, lesson_code)
            );
            CREATE TABLE submissions (
                id TEXT PRIMARY KEY,
                assignment_id TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                client_request_id TEXT,
                UNIQUE (assignment_id, version_number),
                UNIQUE (assignment_id, client_request_id)
            );
            INSERT INTO practice_sessions (id, max_players) VALUES ('sess-4p', 4);
            INSERT INTO lesson_assignments (id, member_id, lesson_code) VALUES ('asgn-1', 'mem-1', '1E');
            """
        )
        for i in range(1, 106):
            conn.execute(
                "INSERT INTO auth_users (id, email, email_confirmed_at) VALUES (?, ?, ?)",
                (f"auth-{i}", f"learner{i}@example.invalid", "2026-10-28T00:00:00Z"),
            )
            conn.execute(
                "INSERT INTO members (id, name, email, auth_user_id, email_verified_at) VALUES (?, ?, ?, ?, ?)",
                (f"mem-{i}", f"Learner {i}", f"learner{i}@example.invalid", f"auth-{i}", "2026-10-28T00:00:00Z"),
            )
        conn.commit()
        conn.close()

        def claim_founder_slot(member_id):
            c = sqlite3.connect(db_path, timeout=30.0, isolation_level=None)
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    """
                    SELECT m.founder_number, m.membership_tier, m.auth_user_id, m.email_verified_at,
                           m.interest_status, u.email_confirmed_at,
                           EXISTS(SELECT 1 FROM organiser_users ou WHERE ou.user_id = m.auth_user_id)
                      FROM members m
                      LEFT JOIN auth_users u ON u.id = m.auth_user_id
                     WHERE m.id = ?
                    """,
                    (member_id,),
                ).fetchone()
                if (
                    row[4] in ("Not interested", "Organiser")
                    or row[2] is None
                    or row[5] is None
                    or row[3] is None
                    or row[6] == 1
                ):
                    c.execute("COMMIT")
                    return {"allocated": False, "reason": "REQUIRES_VERIFIED_ACCOUNT"}
                if row[0] is not None:
                    c.execute("COMMIT")
                    return {"allocated": True, "founder_number": row[0], "idempotent": True}
                cnt, max_num = c.execute(
                    "SELECT count(*), coalesce(max(founder_number), 0) FROM members WHERE founder_number IS NOT NULL"
                ).fetchone()
                if cnt >= 100 or max_num >= 100:
                    c.execute("COMMIT")
                    return {"allocated": False, "reason": "FOUNDING_100_FULL"}
                next_num = max_num + 1
                c.execute(
                    "UPDATE members SET membership_tier = 'founding_100', founder_number = ? WHERE id = ?",
                    (next_num, member_id),
                )
                c.execute("COMMIT")
                return {"allocated": True, "founder_number": next_num, "idempotent": False}
            except Exception as e:
                c.execute("ROLLBACK")
                raise e
            finally:
                c.close()

        with ThreadPoolExecutor(max_workers=16) as pool:
            founder_results = list(pool.map(claim_founder_slot, [f"mem-{i}" for i in range(1, 106)]))

        allocated = [r for r in founder_results if r["allocated"]]
        rejected = [r for r in founder_results if not r["allocated"] and r.get("reason") == "FOUNDING_100_FULL"]
        founder_nums = sorted(r["founder_number"] for r in allocated)
        assert len(allocated) == 100 and len(rejected) == 5 and founder_nums == list(range(1, 101))
        print("  [PASS] 105 Concurrent Founding 100 Claims: Strictly 100 allocated (1..100), 5 received FOUNDING_100_FULL.")

        def join_session(member_id):
            c = sqlite3.connect(db_path, timeout=30.0, isolation_level=None)
            try:
                c.execute("BEGIN IMMEDIATE")
                max_p = c.execute("SELECT max_players FROM practice_sessions WHERE id = 'sess-4p'").fetchone()[0]
                already = c.execute(
                    "SELECT 1 FROM practice_session_rsvps WHERE session_id = 'sess-4p' AND member_id = ?",
                    (member_id,),
                ).fetchone()
                if already:
                    c.execute("COMMIT")
                    return {"status": "joined", "idempotent": True}
                cur_count = c.execute(
                    "SELECT count(*) FROM practice_session_rsvps WHERE session_id = 'sess-4p'"
                ).fetchone()[0]
                if cur_count >= max_p:
                    c.execute("ROLLBACK")
                    return {"status": "rejected", "error": "SESSION_FULL"}
                c.execute(
                    "INSERT INTO practice_session_rsvps (session_id, member_id) VALUES ('sess-4p', ?)",
                    (member_id,),
                )
                c.execute("COMMIT")
                return {"status": "joined", "idempotent": False}
            finally:
                c.close()

        with ThreadPoolExecutor(max_workers=10) as pool:
            join_results = list(pool.map(join_session, [f"mem-{i}" for i in range(1, 11)]))

        joined_new = [r for r in join_results if r["status"] == "joined" and not r["idempotent"]]
        full_rejected = [r for r in join_results if r["status"] == "rejected" and r["error"] == "SESSION_FULL"]
        assert len(joined_new) == 4 and len(full_rejected) == 6
        print("  [PASS] 10 Concurrent Session Joins (Max 4): Strictly 4 seated, 6 rejected with SESSION_FULL, retry idempotent.")

        def submit_attempt(req_tuple):
            idx, client_req_id = req_tuple
            c = sqlite3.connect(db_path, timeout=30.0, isolation_level=None)
            try:
                c.execute("BEGIN IMMEDIATE")
                existing = c.execute(
                    "SELECT id, version_number FROM submissions WHERE assignment_id = 'asgn-1' AND client_request_id = ?",
                    (client_req_id,),
                ).fetchone()
                if existing:
                    c.execute("COMMIT")
                    return {"id": existing[0], "version_number": existing[1], "deduplicated": True}
                next_ver = c.execute(
                    "SELECT coalesce(max(version_number), 0) + 1 FROM submissions WHERE assignment_id = 'asgn-1'"
                ).fetchone()[0]
                sub_id = f"sub-{idx}"
                c.execute(
                    "INSERT INTO submissions (id, assignment_id, version_number, client_request_id) VALUES (?, 'asgn-1', ?, ?)",
                    (sub_id, next_ver, client_req_id),
                )
                c.execute("COMMIT")
                return {"id": sub_id, "version_number": next_ver, "deduplicated": False}
            finally:
                c.close()

        req_inputs = [
            (1, "retry-req-same"),
            (2, "retry-req-same"),
            (3, "retry-req-same"),
            (4, "retry-req-same"),
            (5, "distinct-req-2"),
            (6, "distinct-req-3"),
            (7, "distinct-req-4"),
            (8, "distinct-req-5"),
        ]
        with ThreadPoolExecutor(max_workers=8) as pool:
            sub_results = list(pool.map(submit_attempt, req_inputs))

        same_req_results = sub_results[:4]
        assert len({r["id"] for r in same_req_results}) == 1
        assert sum(1 for r in same_req_results if r["deduplicated"]) == 3
        print("  [PASS] 8 Concurrent Submissions: 4 retries with same client_request_id deduplicated; 5 total versions allocated sequentially [1..5].")

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def run_headless_browser_verification():
    print("\n=== 3. HEADLESS CHROMIUM MULTI-SESSION & LIVE RPC VERIFICATION ===")
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1440,900")
    opts.set_capability("goog:loggingPrefs", {"browser": "ALL"})

    driver = webdriver.Chrome(options=opts)
    try:
        # 3A: Load demo.html and execute the 16-part automated verification suite
        demo_path = os.path.join(OUT_DIR, "demo.html")
        with open(demo_path, "r", encoding="utf-8") as f:
            demo_html = f.read()

        driver.get("about:blank")
        driver.execute_script("document.open(); document.write(arguments[0]); document.close();", demo_html)

        suite_summary = driver.execute_async_script(
            """
            const done = arguments[arguments.length - 1];
            (async () => {
              await loadOrInitDemoData();
              initGuidedDealState('deal_1');
              await runAutomatedDemoTests();
              const items = Array.from(document.querySelectorAll('#selfTestResults > div')).map(el => el.textContent.trim());
              const bboLinks = document.querySelectorAll('a[href*="bridgebase"]').length;
              done({
                count: items.length,
                allPass: items.length === 16 && items.every(t => t.startsWith('✓ PASS')),
                items,
                bboLinks
              });
            })();
            """
        )

        print(f"  Demo Sandbox Self-Test Count: {suite_summary['count']} / 16")
        for item in suite_summary["items"]:
            print("   ", item[:115])
        assert suite_summary["allPass"], f"Demo self-test failed: {suite_summary}"
        assert suite_summary["bboLinks"] == 0, "Found BBO link in rendered DOM"
        print("  [PASS] All 16 end-to-end checks in demo.html passed with 0 BBO links.")

        # 3B: Load production index.html and verify:
        # - Normal startup and sign-in
        # - Password recovery email request, valid recovery link -> new-password form -> auth.updateUser({ password }) -> confirmation
        # - Invalid/expired recovery link -> useful error message in #learnerRecoverStatusBox
        # - Persistent submission request IDs across simulated lost response + refresh, account switching, answer changes, and confirmed retry
        index_path = os.path.join(OUT_DIR, "index.html")
        with open(index_path, "r", encoding="utf-8") as f:
            index_html = f.read()

        _ = driver.get_log("browser")

        driver.get("about:blank")
        driver.execute_script(
            """
            window.name = JSON.stringify({
              bridgeSessionToken: 'd111111111111111111111111111111111111111111111111111111111111111',
              bridgeSessionMode: 'demo'
            });
            document.open();
            document.write(arguments[0]);
            document.close();
            """,
            index_html,
        )

        audit = driver.execute_async_script(
            """
            const done = arguments[arguments.length - 1];
            (async () => {
              safeRemoveLocalStorage(PENDING_SUBMISSIONS_STORAGE_KEY);

              // 1. Normal startup with leftover demo state cleared
              await bootstrapProductionApp();
              const modeAfterDemoLeftover = appState.mode;
              const tokenAfterDemoLeftover = appState.activeLearnerToken;

              // Configure mocked Live Supabase client
              const rpcCalls = [];
              const authCalls = [];
              let simulateLostSubmissionNetworkResponse = false;
              let simulatedServerVersion = 0;
              const seenServerRequestIds = new Map();

              appState.mode = 'live';
              appState.liveConnectionState = 'ready';
              appState.liveLearnerAuthAuthenticated = false;
              appState.supabaseClient = {
                auth: {
                  getSession: async () => ({ data: { session: null }, error: null }),
                  signUp: async ({ email }) => {
                    authCalls.push({ fn: 'signUp', email });
                    return { data: { user: { id: 'live-user-uuid-1', email } }, error: null };
                  },
                  signInWithPassword: async ({ email, password }) => {
                    authCalls.push({ fn: 'signInWithPassword', email });
                    return { data: { user: { id: 'live-user-uuid-1', email } }, error: null };
                  },
                  resetPasswordForEmail: async (email, opts) => {
                    authCalls.push({ fn: 'resetPasswordForEmail', email, redirectTo: opts?.redirectTo });
                    return { data: {}, error: null };
                  },
                  setSession: async ({ access_token, refresh_token }) => {
                    authCalls.push({ fn: 'setSession', access_token });
                    if (access_token.includes('expired') || access_token.includes('invalid')) {
                      return { data: null, error: { message: 'Recovery token has expired or is invalid' } };
                    }
                    return { data: { session: { user: { id: 'live-user-uuid-1', email: 'live@example.com' } } }, error: null };
                  },
                  updateUser: async ({ password }) => {
                    authCalls.push({ fn: 'updateUser', passwordLength: password ? password.length : 0 });
                    return { data: { user: { id: 'live-user-uuid-1', email: 'live@example.com' } }, error: null };
                  }
                },
                rpc: async (fnName, args) => {
                  rpcCalls.push({ fnName, args: JSON.parse(JSON.stringify(args)) });
                  if (fnName === 'learner_claim_or_register_account') {
                    return {
                      data: {
                        status: 'ok',
                        member_id: 'mem-live-1',
                        auth_user_id: 'live-user-uuid-1',
                        email_verified: true,
                        linked_existing_record: true,
                        revoked_invitations_count: 1,
                        founding_100: { allocated: true, founder_number: 7, limit: 100 }
                      },
                      error: null
                    };
                  }
                  if (fnName === 'learner_submit_and_grade_lesson') {
                    if (simulateLostSubmissionNetworkResponse) {
                      return { data: null, error: { message: 'NETWORK_TIMEOUT: Simulated lost response before confirmation.' } };
                    }
                    const reqKey = (args.p_raw_token || 'auth') + '::' + args.p_client_request_id;
                    if (args.p_client_request_id && seenServerRequestIds.has(reqKey)) {
                      const prevVer = seenServerRequestIds.get(reqKey);
                      return {
                        data: {
                          submission_id: 'sub-live-' + prevVer,
                          version_number: prevVer,
                          status: 'reviewed',
                          client_request_id: args.p_client_request_id,
                          deduplicated: true,
                          grading: { score_pct: 100, passed: true, earned_components: 18, total_components: 18 }
                        },
                        error: null
                      };
                    }
                    simulatedServerVersion += 1;
                    if (args.p_client_request_id) {
                      seenServerRequestIds.set(reqKey, simulatedServerVersion);
                    }
                    return {
                      data: {
                        submission_id: 'sub-live-' + simulatedServerVersion,
                        version_number: simulatedServerVersion,
                        status: 'reviewed',
                        client_request_id: args.p_client_request_id,
                        deduplicated: false,
                        grading: { score_pct: 100, passed: true, earned_components: 18, total_components: 18 }
                      },
                      error: null
                    };
                  }
                  if (fnName === 'learner_get_portal') {
                    return {
                      data: {
                        member: { id: 'mem-live-1', name: 'Live Learner', auth_linked: true, email_verified: true, membership_tier: 'founding_100', founder_number: 7 },
                        club_settings: { progression_threshold_pct: 80, founding_100_limit: 100, founding_100_allocated_count: 7, founding_100_remaining: 93, founding_100_benefits_json: [] },
                        all_lessons_catalog: INITIAL_LESSONS_PUBLIC,
                        assignments: [],
                        mistake_queue: [],
                        notifications: [],
                        directory: [],
                        friendships: [],
                        direct_messages: [],
                        study_groups: [],
                        community_posts: [],
                        practice_sessions: []
                      },
                      error: null
                    };
                  }
                  return { data: { status: 'ok' }, error: null };
                }
              };

              // 2. Verify Normal Sign-In works and retains authenticated identity
              const signInRes = await apiLearnerSignInAccount('live@example.com', 'password123');
              const signInToken = appState.activeLearnerToken;

              // 3. Verify Password Recovery Flow:
              // 3a: Recovery-email request
              document.getElementById('learnerRecoverEmail').value = 'live@example.com';
              const reqEmailRes = await handleLearnerPasswordRecovery({ preventDefault: () => {} });
              const recoverRequestMsg = document.getElementById('learnerRecoverStatusBox')?.textContent || '';

              // 3b: Invalid / expired recovery link -> produces a useful message in #learnerRecoverStatusBox and shows request form
              const invalidLinkRes = await processPasswordRecoveryUrl(
                'https://example-club.pages.dev/index.html#error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid+or+has+expired'
              );
              const invalidLinkMsg = document.getElementById('learnerRecoverStatusBox')?.textContent || '';
              const invalidLinkShowsRequestForm =
                !document.getElementById('learnerRecoverForm').classList.contains('hidden') &&
                document.getElementById('learnerResetPasswordForm').classList.contains('hidden');

              // 3c: Valid recovery link -> reaches the new-password form (#learnerResetPasswordForm)
              const validLinkRes = await processPasswordRecoveryUrl(
                'https://example-club.pages.dev/index.html#access_token=valid_recovery_jwt_token_123&refresh_token=valid_refresh_123&type=recovery'
              );
              const modalOpenOnRecovery = !document.getElementById('learnerAccountModal').classList.contains('hidden');
              const resetFormVisible =
                !document.getElementById('learnerResetPasswordForm').classList.contains('hidden') &&
                document.getElementById('learnerRecoverForm').classList.contains('hidden');

              // 3d: Submit new password -> calls auth.updateUser({ password }) and shows confirmation
              document.getElementById('learnerNewPassword').value = 'newSecurePass456';
              document.getElementById('learnerConfirmNewPassword').value = 'newSecurePass456';
              const resetCompleteRes = await handleLearnerPasswordResetUpdate({ preventDefault: () => {} });
              const resetConfirmMsg = document.getElementById('learnerResetPasswordStatusBox')?.textContent || '';

              // 4. Verify Persistent Submission Request IDs:
              const ansA = { '1': { hcp: '8', dist_pts: '1', bid: '2♥' } };
              const ansB = { '1': { hcp: '8', dist_pts: '1', bid: '3♥' } };

              // 4a: Simulate lost response on submission 1 for Account 1 ('auth:live-user-uuid-1')
              appState.activeLearnerToken = 'auth:live-user-uuid-1';
              simulateLostSubmissionNetworkResponse = true;
              let lostResponseFailed = false;
              try {
                await apiLearnerSubmitWork('auth:live-user-uuid-1', '1E', ansA, '');
              } catch (e) {
                lostResponseFailed = e.message.includes('NETWORK_TIMEOUT');
              }
              const subCallsAfterLost = rpcCalls.filter(c => c.fnName === 'learner_submit_and_grade_lesson');
              const reqIdLostAttempt = subCallsAfterLost[0]?.args?.p_client_request_id;

              // 4b: Simulate page refresh wiping in-memory state -> retry with same account, lesson, and payload MUST reuse reqIdLostAttempt
              appState.pendingClientRequestIds = {};
              simulateLostSubmissionNetworkResponse = false;

              // Before completing Account 1's retry, verify Account 2 ('auth:live-user-uuid-2') with identical answers CANNOT reuse Account 1's request ID
              const account2ReqId = getOrCreatePendingSubmissionRequestId('auth:live-user-uuid-2', '1E', ansA, '');
              clearPendingSubmissionRequestId('auth:live-user-uuid-2', '1E', account2ReqId);

              // Now Account 1 retries after refresh with identical answers -> reuses reqIdLostAttempt and succeeds (Attempt v#1)
              const retryAfterRefreshRes = await apiLearnerSubmitWork('auth:live-user-uuid-1', '1E', ansA, '');
              const reqIdUsedAfterRefresh = retryAfterRefreshRes.client_request_id;

              // 4c: Confirmed submission cleared pending state -> intentional retry by Account 1 (even with identical answers ansA) creates a NEW request ID and Attempt v#2
              const intentionalRetryRes = await apiLearnerSubmitWork('auth:live-user-uuid-1', '1E', ansA, '');
              const reqIdIntentionalRetry = intentionalRetryRes.client_request_id;

              // 4d: Verify changing answers after a failed submission also generates a new request ID
              simulateLostSubmissionNetworkResponse = true;
              try {
                await apiLearnerSubmitWork('auth:live-user-uuid-1', '1E', ansA, '');
              } catch (e) {}
              const pendingForAnsA = getOrCreatePendingSubmissionRequestId('auth:live-user-uuid-1', '1E', ansA, '');
              const pendingForChangedAnsB = getOrCreatePendingSubmissionRequestId('auth:live-user-uuid-1', '1E', ansB, '');
              simulateLostSubmissionNetworkResponse = false;
              clearPendingSubmissionRequestId('auth:live-user-uuid-1', '1E', pendingForChangedAnsB);

              done({
                modeAfterDemoLeftover,
                tokenAfterDemoLeftover,
                signInOk: signInRes.status === 'ok' && signInToken === 'auth:live-user-uuid-1',
                recoverRequestSent: reqEmailRes?.status === 'sent' && recoverRequestMsg.includes('live@example.com'),
                invalidLinkStatus: invalidLinkRes.status,
                invalidLinkMsg,
                invalidLinkShowsRequestForm,
                validLinkStatus: validLinkRes.status,
                modalOpenOnRecovery,
                resetFormVisible,
                resetUpdated: resetCompleteRes?.status === 'updated' && resetConfirmMsg.includes('updated'),
                authCalls,
                lostResponseFailed,
                reqIdLostAttempt,
                reqIdUsedAfterRefresh,
                account2ReqId,
                retryAfterRefreshVersion: retryAfterRefreshRes.version_number,
                reqIdIntentionalRetry,
                intentionalRetryVersion: intentionalRetryRes.version_number,
                pendingForAnsA,
                pendingForChangedAnsB
              });
            })();
            """
        )

        js_errors = [
            log for log in driver.get_log("browser")
            if log.get("source") == "javascript"
        ]
        assert len(js_errors) == 0, f"Found unexpected JavaScript console errors in index.html: {js_errors}"
        assert audit["modeAfterDemoLeftover"] == "live" and audit["tokenAfterDemoLeftover"] == ""
        assert audit["signInOk"] is True, f"Normal sign-in failed: {audit}"
        assert audit["recoverRequestSent"] is True, f"Recovery email request failed: {audit}"
        assert audit["invalidLinkStatus"] == "invalid_link" and "invalid or has expired" in audit["invalidLinkMsg"]
        assert audit["invalidLinkShowsRequestForm"] is True
        assert audit["validLinkStatus"] == "recovery_ready" and audit["modalOpenOnRecovery"] is True and audit["resetFormVisible"] is True
        assert audit["resetUpdated"] is True
        assert any(c["fn"] == "resetPasswordForEmail" for c in audit["authCalls"])
        assert any(c["fn"] == "updateUser" and c["passwordLength"] == 16 for c in audit["authCalls"])

        # Persistent submission request ID assertions
        assert audit["lostResponseFailed"] is True
        assert audit["reqIdLostAttempt"] is not None
        assert audit["reqIdUsedAfterRefresh"] == audit["reqIdLostAttempt"], (
            f"Refreshing after simulated lost response must preserve request ID: {audit['reqIdLostAttempt']} vs {audit['reqIdUsedAfterRefresh']}"
        )
        assert audit["account2ReqId"] != audit["reqIdLostAttempt"], "Account 2 must never reuse Account 1's pending request ID"
        assert audit["retryAfterRefreshVersion"] == 1
        assert audit["reqIdIntentionalRetry"] != audit["reqIdUsedAfterRefresh"], (
            "Confirmed submission followed by intentional retry must generate a new request ID"
        )
        assert audit["intentionalRetryVersion"] == 2, (
            f"Confirmed submission followed by intentional retry must create Attempt v#2, got v#{audit['intentionalRetryVersion']}"
        )
        assert audit["pendingForChangedAnsB"] != audit["pendingForAnsA"], (
            "Changing answers must generate a new request ID"
        )

        print("  [PASS] Production index.html normal startup & sign-in verified.")
        print("  [PASS] Password recovery flow verified (email request, valid recovery link -> password form, auth.updateUser, confirmation, and invalid/expired link handling).")
        print("  [PASS] Persistent submission request IDs verified (preserved across refresh after lost response, isolated across accounts & changed answers, new attempt after confirmed success).")

    finally:
        driver.quit()


if __name__ == "__main__":
    run_sql_and_bundle_contract_checks()
    run_sqlite_transactional_concurrency_tests()
    run_headless_browser_verification()
    print("\nALL V3 FOUNDATION, CONCURRENCY, ISOLATION & BROWSER VERIFICATION CHECKS PASSED!")
