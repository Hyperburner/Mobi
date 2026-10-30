-- =============================================================================
-- MIGRATION V3.1 (FOR EXISTING V3 DATABASES):
-- AUTHORITATIVE EMAIL VERIFICATION & SAFE RETIREMENT OF LEGACY INVITATION ACCESS
-- =============================================================================
-- Idempotent migration for an existing V3 PostgreSQL / Supabase database:
-- 1. Removes the `now()` fallback on `public.members.email_verified_at` and reconciles
--    existing rows directly against `auth.users.email_confirmed_at`.
-- 2. Requires verified email (`auth.users.email_confirmed_at IS NOT NULL`) for
--    email-only profile linking (`EMAIL_NOT_VERIFIED`) and Founding 100 eligibility
--    (`REQUIRES_VERIFIED_ACCOUNT`), while preserving organiser restrictions.
-- 3. Safely retires legacy bearer invitation access when a learner links a durable account:
--    - Revokes all unrevoked rows in `public.learner_invitations` for linked profiles.
--    - Rejects bearer token access to linked profiles in `public.resolve_learner_identity`.
--    - Prevents issuing new bearer invitations for linked profiles in `public.organiser_issue_invitation`.
--    - Requires authenticated account ownership (`auth.uid()` matching `members.auth_user_id`)
--      for private Direct Messaging (`learner_send_direct_message`, `learner_get_direct_messages`,
--      `learner_report_direct_message`, and `direct_messages` in `learner_get_portal`).
--    - Preserves authenticated access through `public.resolve_learner_identity`.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. RECONCILE EXISTING V3 DATA (EMAIL VERIFICATION & LEGACY INVITATION RETIREMENT)
-- -----------------------------------------------------------------------------

-- Sync members.email_verified_at strictly with auth.users.email_confirmed_at
UPDATE public.members m
   SET email_verified_at = u.email_confirmed_at,
       updated_at = now()
  FROM auth.users u
 WHERE m.auth_user_id = u.id
   AND m.email_verified_at IS DISTINCT FROM u.email_confirmed_at;

-- Clear email_verified_at on any unlinked member row
UPDATE public.members
   SET email_verified_at = NULL,
       updated_at = now()
 WHERE auth_user_id IS NULL
   AND email_verified_at IS NOT NULL;

-- Ensure Founding 100 slots are held only by active non-organiser learners with verified email
UPDATE public.members m
   SET membership_tier = 'standard',
       founder_number = NULL,
       founder_granted_at = NULL,
       updated_at = now()
 WHERE m.founder_number IS NOT NULL
   AND (
       m.auth_user_id IS NULL
       OR m.email_verified_at IS NULL
       OR m.interest_status IN ('Not interested', 'Organiser')
       OR EXISTS (SELECT 1 FROM public.organiser_users ou WHERE ou.user_id = m.auth_user_id)
   );

-- Revoke any remaining active bearer invitations for profiles linked to a durable account
UPDATE public.learner_invitations li
   SET revoked_at = now()
  FROM public.members m
 WHERE li.member_id = m.id
   AND m.auth_user_id IS NOT NULL
   AND li.revoked_at IS NULL;

-- -----------------------------------------------------------------------------
-- 2. UPDATED IDENTITY RESOLVER, FOUNDING 100 ALLOCATOR & ACCOUNT LINKING RPCS
-- -----------------------------------------------------------------------------

-- Resolves learner identity from EITHER a durable Supabase Auth session (`auth.uid()`)
-- OR a valid SHA-256 learner invitation token (`p_raw_token`) for unlinked profiles.
-- Once a learner profile is linked to a durable account (`members.auth_user_id IS NOT NULL`),
-- legacy bearer invitation access to that profile is strictly rejected.
CREATE OR REPLACE FUNCTION public.resolve_learner_identity(p_raw_token text DEFAULT NULL)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_auth_member RECORD;
    v_clean text;
    v_hash text;
    v_inv RECORD;
    v_token_member RECORD;
BEGIN
    v_uid := auth.uid();
    v_clean := lower(trim(coalesce(p_raw_token, '')));

    -- 1. Check if caller has a linked durable learner account via Supabase Auth
    IF v_uid IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM public.organiser_users ou WHERE ou.user_id = v_uid) THEN
            RAISE EXCEPTION 'FORBIDDEN: Organiser accounts cannot access learner endpoints.'
                USING ERRCODE = '42501';
        END IF;

        SELECT m.id, m.interest_status
          INTO v_auth_member
          FROM public.members m
         WHERE m.auth_user_id = v_uid
         LIMIT 1;

        IF FOUND THEN
            IF v_auth_member.interest_status IN ('Not interested', 'Organiser') THEN
                RAISE EXCEPTION 'INACTIVE_LEARNER: This learner profile is not active for lessons.'
                    USING ERRCODE = '42501';
            END IF;

            -- If a hex invitation token was also passed, ensure it does not belong to a different person
            IF char_length(v_clean) >= 32 AND v_clean ~ '^[0-9a-f]+$' THEN
                v_hash := encode(extensions.digest(convert_to(v_clean, 'UTF8'), 'sha256'), 'hex');
                SELECT li.member_id INTO v_inv
                  FROM public.learner_invitations li
                 WHERE li.token_hash = v_hash
                 LIMIT 1;
                IF FOUND AND v_inv.member_id <> v_auth_member.id THEN
                    RAISE EXCEPTION 'ACCOUNT_MISMATCH: This invitation token belongs to a different learner profile than your signed-in account.'
                        USING ERRCODE = '42501';
                END IF;
            END IF;
            RETURN v_auth_member.id;
        END IF;
    END IF;

    -- 2. Otherwise validate the raw invitation token via SHA-256 hash lookup (for unlinked profiles only)
    IF char_length(v_clean) < 32 OR v_clean !~ '^[0-9a-f]+$' THEN
        IF v_uid IS NOT NULL THEN
            RAISE EXCEPTION 'ACCOUNT_NOT_LINKED: Your signed-in account does not have a linked learner profile yet. Complete registration or link your invitation token first.'
                USING ERRCODE = '28000';
        END IF;
        RAISE EXCEPTION 'INVALID_TOKEN: Please sign in with your learner account or use a valid invitation link.'
            USING ERRCODE = '28000';
    END IF;

    v_hash := encode(extensions.digest(convert_to(v_clean, 'UTF8'), 'sha256'), 'hex');

    SELECT li.id, li.member_id, li.expires_at, li.revoked_at
      INTO v_inv
      FROM public.learner_invitations li
     WHERE li.token_hash = v_hash
     LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_TOKEN: Invitation link not recognised.'
            USING ERRCODE = '28000';
    END IF;

    SELECT m.id, m.interest_status, m.auth_user_id
      INTO v_token_member
      FROM public.members m
     WHERE m.id = v_inv.member_id;

    IF NOT FOUND OR v_token_member.interest_status IN ('Not interested', 'Organiser') THEN
        RAISE EXCEPTION 'INACTIVE_LEARNER: This learner profile is not active for lessons.'
            USING ERRCODE = '42501';
    END IF;

    -- Reject bearer access to profiles that have linked a durable account
    IF v_token_member.auth_user_id IS NOT NULL THEN
        RAISE EXCEPTION 'ACCOUNT_LINKED: This learner profile is linked to a durable account (REVOKED_TOKEN). Legacy bearer invitation access is retired—please sign in with your email and password.'
            USING ERRCODE = '28000';
    END IF;

    IF v_inv.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'REVOKED_TOKEN: This invitation link has been revoked by the organiser.'
            USING ERRCODE = '28000';
    END IF;

    IF v_inv.expires_at <= now() THEN
        RAISE EXCEPTION 'EXPIRED_TOKEN: This invitation link has expired. Sign in with your durable learner account or ask the organiser for a new link.'
            USING ERRCODE = '28000';
    END IF;

    UPDATE public.learner_invitations
       SET last_used_at = now()
     WHERE id = v_inv.id;

    RETURN v_inv.member_id;
END;
$$;

REVOKE ALL ON FUNCTION public.resolve_learner_identity(text) FROM PUBLIC, anon, authenticated;

-- Keep validate_learner_token delegating to resolve_learner_identity for full backward compatibility
CREATE OR REPLACE FUNCTION public.validate_learner_token(p_raw_token text DEFAULT NULL)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
BEGIN
    RETURN public.resolve_learner_identity(p_raw_token);
END;
$$;

REVOKE ALL ON FUNCTION public.validate_learner_token(text) FROM PUBLIC, anon, authenticated;

-- Atomically allocates a Founding 100 Lifetime Premium slot (1..100) to an eligible
-- verified learner account using transaction-scoped advisory lock 77100.
-- Reads verification status strictly from auth.users.email_confirmed_at and preserves organiser restrictions.
CREATE OR REPLACE FUNCTION public.allocate_founding_membership_if_eligible(p_member_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_member RECORD;
    v_auth_confirmed_at timestamptz;
    v_limit integer;
    v_allocated_count integer;
    v_max_founder_num integer;
    v_next_num integer;
BEGIN
    -- Exclusive transaction lock prevents concurrent race conditions across simultaneous claims
    PERFORM pg_advisory_xact_lock(77100);

    SELECT m.id, m.name, m.interest_status, m.auth_user_id, m.email_verified_at,
           m.membership_tier, m.founder_number, m.founder_granted_at
      INTO v_member
      FROM public.members m
     WHERE m.id = p_member_id
       FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND: Member record not found.'
            USING ERRCODE = 'P0002';
    END IF;

    -- Read authoritative email verification status from auth.users.email_confirmed_at
    v_auth_confirmed_at := NULL;
    IF v_member.auth_user_id IS NOT NULL THEN
        SELECT u.email_confirmed_at
          INTO v_auth_confirmed_at
          FROM auth.users u
         WHERE u.id = v_member.auth_user_id;

        IF v_member.email_verified_at IS DISTINCT FROM v_auth_confirmed_at THEN
            UPDATE public.members
               SET email_verified_at = v_auth_confirmed_at,
                   updated_at = now()
             WHERE id = p_member_id;
            v_member.email_verified_at := v_auth_confirmed_at;
        END IF;
    END IF;

    SELECT least(coalesce(cs.founding_100_limit, 100), 100)
      INTO v_limit
      FROM public.club_settings cs
     WHERE cs.id = 1;
    v_limit := coalesce(v_limit, 100);

    -- Eligibility check: must be an active non-organiser learner with a linked account
    -- whose email is verified in auth.users.email_confirmed_at
    IF v_member.interest_status IN ('Not interested', 'Organiser')
       OR v_member.auth_user_id IS NULL
       OR v_auth_confirmed_at IS NULL
       OR v_member.email_verified_at IS NULL
       OR EXISTS (SELECT 1 FROM public.organiser_users ou WHERE ou.user_id = v_member.auth_user_id) THEN
        SELECT count(*)::integer INTO v_allocated_count
          FROM public.members
         WHERE founder_number IS NOT NULL;

        RETURN jsonb_build_object(
            'allocated', false,
            'reason', 'REQUIRES_VERIFIED_ACCOUNT',
            'membership_tier', v_member.membership_tier,
            'founder_number', NULL,
            'allocated_count', v_allocated_count,
            'limit', v_limit
        );
    END IF;

    -- Already allocated Founding 100: return idempotently
    IF v_member.founder_number IS NOT NULL THEN
        SELECT count(*)::integer INTO v_allocated_count
          FROM public.members
         WHERE founder_number IS NOT NULL;

        RETURN jsonb_build_object(
            'allocated', true,
            'idempotent', true,
            'membership_tier', v_member.membership_tier,
            'founder_number', v_member.founder_number,
            'founder_granted_at', v_member.founder_granted_at,
            'allocated_count', v_allocated_count,
            'limit', v_limit
        );
    END IF;

    SELECT count(*)::integer, coalesce(max(founder_number), 0)::integer
      INTO v_allocated_count, v_max_founder_num
      FROM public.members
     WHERE founder_number IS NOT NULL;

    IF v_allocated_count >= v_limit OR v_max_founder_num >= 100 THEN
        RETURN jsonb_build_object(
            'allocated', false,
            'reason', 'FOUNDING_100_FULL',
            'membership_tier', 'standard',
            'founder_number', NULL,
            'allocated_count', v_allocated_count,
            'limit', v_limit
        );
    END IF;

    v_next_num := v_max_founder_num + 1;

    UPDATE public.members
       SET membership_tier = 'founding_100',
           founder_number = v_next_num,
           founder_granted_at = now(),
           updated_at = now()
     WHERE id = p_member_id;

    INSERT INTO public.member_notifications (member_id, kind, title, body)
    VALUES (
        p_member_id,
        'founding_100',
        format('Founding 100 Lifetime Premium Awarded (#%s of %s)', v_next_num, v_limit),
        format('Welcome, %s! Your verified account holds Founding Member #%s with lifetime Premium club benefits.', v_member.name, v_next_num)
    );

    RETURN jsonb_build_object(
        'allocated', true,
        'idempotent', false,
        'membership_tier', 'founding_100',
        'founder_number', v_next_num,
        'founder_granted_at', now(),
        'allocated_count', v_allocated_count + 1,
        'limit', v_limit
    );
END;
$$;

REVOKE ALL ON FUNCTION public.allocate_founding_membership_if_eligible(uuid) FROM PUBLIC, anon, authenticated;

-- Allows an authenticated Supabase Auth user (`auth.uid()`) to either:
-- (a) claim & link an existing invitation-token learner profile (`p_raw_token`), preserving
--     all assignments, submissions, feedback, mistake queue, friendships, and sessions,
--     and immediately revoking their legacy bearer invitations;
-- (b) link an existing unlinked member row matching their verified email (`auth.users.email_confirmed_at IS NOT NULL`); or
-- (c) register a new durable learner profile with Lesson 1E unlocked;
-- and atomically claim a Founding 100 Lifetime Premium spot if their email is verified.
CREATE OR REPLACE FUNCTION public.learner_claim_or_register_account(
    p_raw_token text DEFAULT NULL,
    p_display_name text DEFAULT '',
    p_experience text DEFAULT 'New to bridge',
    p_availability_pkt text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_auth_email text;
    v_email_confirmed_at timestamptz;
    v_clean_token text;
    v_hash text;
    v_inv RECORD;
    v_member RECORD;
    v_member_id uuid;
    v_linked_existing boolean := false;
    v_revoked_invitations integer := 0;
    v_clean_name text;
    v_clean_avail text;
    v_exp text;
    v_founder_result jsonb;
BEGIN
    v_uid := auth.uid();
    IF v_uid IS NULL THEN
        RAISE EXCEPTION 'UNAUTHENTICATED: Please sign in with your email and password before linking or registering your learner account.'
            USING ERRCODE = '28000';
    END IF;

    IF EXISTS (SELECT 1 FROM public.organiser_users ou WHERE ou.user_id = v_uid) THEN
        RAISE EXCEPTION 'FORBIDDEN: Organiser accounts cannot be registered as learner profiles.'
            USING ERRCODE = '42501';
    END IF;

    -- Read authoritative verified email state directly from auth.users (no now() fallback)
    SELECT u.email, u.email_confirmed_at
      INTO v_auth_email, v_email_confirmed_at
      FROM auth.users u
     WHERE u.id = v_uid;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'UNAUTHENTICATED: Authenticated user record not found in auth.users.'
            USING ERRCODE = '28000';
    END IF;

    v_clean_name := public.sanitize_club_text(p_display_name);
    v_clean_avail := public.sanitize_club_text(p_availability_pkt);
    v_exp := CASE
        WHEN p_experience IN ('New to bridge', 'Learning', 'Comfortable playing', 'Can help teach') THEN p_experience
        ELSE 'New to bridge'
    END;

    -- 1. Check if this auth.uid() already owns a member profile
    SELECT * INTO v_member
      FROM public.members m
     WHERE m.auth_user_id = v_uid
       FOR UPDATE;

    IF FOUND THEN
        IF v_member.interest_status IN ('Not interested', 'Organiser') THEN
            RAISE EXCEPTION 'FORBIDDEN: Organiser or inactive profiles cannot be used as learner accounts.'
                USING ERRCODE = '42501';
        END IF;

        v_member_id := v_member.id;
        v_linked_existing := true;
        UPDATE public.members
           SET email = coalesce(nullif(email, ''), v_auth_email),
               email_verified_at = v_email_confirmed_at,
               name = CASE WHEN char_length(v_clean_name) > 0 THEN v_clean_name ELSE name END,
               availability_pkt = CASE WHEN char_length(v_clean_avail) > 0 THEN v_clean_avail ELSE availability_pkt END,
               updated_at = now()
         WHERE id = v_member_id;
    ELSE
        -- 2. If an invitation token was provided, link that existing learner profile
        v_clean_token := lower(trim(coalesce(p_raw_token, '')));
        IF char_length(v_clean_token) >= 32 AND v_clean_token ~ '^[0-9a-f]+$' THEN
            v_hash := encode(extensions.digest(convert_to(v_clean_token, 'UTF8'), 'sha256'), 'hex');
            SELECT li.id, li.member_id, li.revoked_at, li.expires_at
              INTO v_inv
              FROM public.learner_invitations li
             WHERE li.token_hash = v_hash
             LIMIT 1;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'INVALID_TOKEN: The invitation token to link was not recognised.'
                    USING ERRCODE = '28000';
            END IF;

            IF v_inv.revoked_at IS NOT NULL OR v_inv.expires_at <= now() THEN
                RAISE EXCEPTION 'EXPIRED_TOKEN: Cannot link a revoked or expired invitation token.'
                    USING ERRCODE = '28000';
            END IF;

            SELECT * INTO v_member
              FROM public.members m
             WHERE m.id = v_inv.member_id
               FOR UPDATE;

            IF NOT FOUND OR v_member.interest_status IN ('Not interested', 'Organiser') THEN
                RAISE EXCEPTION 'FORBIDDEN: Cannot link an organiser or inactive member profile.'
                    USING ERRCODE = '42501';
            END IF;

            IF v_member.auth_user_id IS NOT NULL AND v_member.auth_user_id <> v_uid THEN
                RAISE EXCEPTION 'ALREADY_CLAIMED: This invitation profile is already linked to another durable account.'
                    USING ERRCODE = '42501';
            END IF;

            v_member_id := v_member.id;
            v_linked_existing := true;

            UPDATE public.members
               SET auth_user_id = v_uid,
                   email = coalesce(nullif(email, ''), v_auth_email),
                   email_verified_at = v_email_confirmed_at,
                   name = CASE WHEN char_length(v_clean_name) > 0 THEN v_clean_name ELSE name END,
                   availability_pkt = CASE WHEN char_length(v_clean_avail) > 0 THEN v_clean_avail ELSE availability_pkt END,
                   interest_status = CASE WHEN interest_status IN ('Not contacted', 'Awaiting reply') THEN 'Interested' ELSE interest_status END,
                   updated_at = now()
             WHERE id = v_member_id;
        END IF;

        -- 3. Otherwise check if an unlinked member row matches the user's email
        --    (Email-only profile linking strictly requires a verified email in auth.users.email_confirmed_at)
        IF v_member_id IS NULL AND v_auth_email IS NOT NULL THEN
            SELECT * INTO v_member
              FROM public.members m
             WHERE lower(trim(coalesce(m.email, ''))) = lower(trim(v_auth_email))
               AND m.auth_user_id IS NULL
               AND m.interest_status NOT IN ('Not interested', 'Organiser')
             ORDER BY m.created_at ASC
             LIMIT 1
               FOR UPDATE;

            IF FOUND THEN
                IF v_email_confirmed_at IS NULL THEN
                    RAISE EXCEPTION 'EMAIL_NOT_VERIFIED: Verified email is required to link an existing club member profile by email.'
                        USING ERRCODE = '42501';
                END IF;

                v_member_id := v_member.id;
                v_linked_existing := true;
                UPDATE public.members
                   SET auth_user_id = v_uid,
                       email_verified_at = v_email_confirmed_at,
                       name = CASE WHEN char_length(v_clean_name) > 0 THEN v_clean_name ELSE name END,
                       availability_pkt = CASE WHEN char_length(v_clean_avail) > 0 THEN v_clean_avail ELSE availability_pkt END,
                       interest_status = CASE WHEN interest_status IN ('Not contacted', 'Awaiting reply') THEN 'Interested' ELSE interest_status END,
                       updated_at = now()
                 WHERE id = v_member_id;
            END IF;
        END IF;

        -- 4. Otherwise create a new durable learner member record and unlock Lesson 1E
        IF v_member_id IS NULL THEN
            IF char_length(v_clean_name) = 0 THEN
                v_clean_name := coalesce(nullif(split_part(coalesce(v_auth_email, ''), '@', 1), ''), 'Club Learner');
            END IF;

            INSERT INTO public.members (
                name, email, interest_status, availability_pkt, experience,
                auth_user_id, email_verified_at
            ) VALUES (
                v_clean_name, v_auth_email, 'Interested', v_clean_avail, v_exp,
                v_uid, v_email_confirmed_at
            )
            RETURNING id INTO v_member_id;
        END IF;
    END IF;

    -- Retire and revoke all legacy bearer invitations for this linked member profile
    UPDATE public.learner_invitations
       SET revoked_at = now()
     WHERE member_id = v_member_id
       AND revoked_at IS NULL;
    GET DIAGNOSTICS v_revoked_invitations = ROW_COUNT;

    -- Ensure Lesson 1E is assigned to the durable learner account
    INSERT INTO public.lesson_assignments (member_id, lesson_code, status)
    VALUES (v_member_id, '1E', 'Not started')
    ON CONFLICT (member_id, lesson_code) DO NOTHING;

    -- Atomically allocate Founding 100 Lifetime Premium if eligible
    v_founder_result := public.allocate_founding_membership_if_eligible(v_member_id);

    RETURN jsonb_build_object(
        'status', 'ok',
        'member_id', v_member_id,
        'auth_user_id', v_uid,
        'email_verified', (v_email_confirmed_at IS NOT NULL),
        'email_verified_at', v_email_confirmed_at,
        'linked_existing_record', v_linked_existing,
        'revoked_invitations_count', v_revoked_invitations,
        'founding_100', v_founder_result
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_claim_or_register_account(text, text, text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.learner_claim_or_register_account(text, text, text, text) TO authenticated;

-- -----------------------------------------------------------------------------
-- 3. PREVENT ISSUING NEW BEARER INVITATIONS FOR LINKED PROFILES
-- -----------------------------------------------------------------------------

-- Prevent issuing new bearer invitations for profiles linked to a durable account
CREATE OR REPLACE FUNCTION public.organiser_issue_invitation(
    p_member_id uuid,
    p_expires_in_days integer DEFAULT 14
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_member RECORD;
    v_raw_token text;
    v_token_hash text;
    v_prefix text;
    v_expires_at timestamptz;
    v_inv_id uuid;
BEGIN
    v_uid := public.assert_is_organiser();

    IF p_expires_in_days IS NULL OR p_expires_in_days < 1 OR p_expires_in_days > 365 THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Expiration must be between 1 and 365 days.'
            USING ERRCODE = '22023';
    END IF;

    SELECT m.id, m.interest_status, m.auth_user_id
      INTO v_member
      FROM public.members m
     WHERE m.id = p_member_id
       FOR UPDATE;

    IF NOT FOUND OR v_member.interest_status = 'Organiser' THEN
        RAISE EXCEPTION 'NOT_FOUND: Valid learner record not found.'
            USING ERRCODE = 'P0002';
    END IF;

    IF v_member.auth_user_id IS NOT NULL THEN
        RAISE EXCEPTION 'ACCOUNT_LINKED: Cannot issue a bearer invitation link for a learner profile that is already linked to a durable account.'
            USING ERRCODE = '42501';
    END IF;

    -- Revoke any existing active invitations for this member
    UPDATE public.learner_invitations
       SET revoked_at = now()
     WHERE member_id = p_member_id
       AND revoked_at IS NULL;

    -- 32 random bytes = 64 hex chars (256 bits of cryptographic entropy)
    v_raw_token := encode(extensions.gen_random_bytes(32), 'hex');
    v_token_hash := encode(extensions.digest(convert_to(v_raw_token, 'UTF8'), 'sha256'), 'hex');
    v_prefix := substr(v_raw_token, 1, 8);
    v_expires_at := now() + make_interval(days => p_expires_in_days);

    INSERT INTO public.learner_invitations (
        member_id, token_hash, token_prefix, expires_at, created_by
    ) VALUES (
        p_member_id, v_token_hash, v_prefix, v_expires_at, v_uid
    )
    RETURNING id INTO v_inv_id;

    -- Ensure Lesson 1E is assigned when issuing an invitation if no lesson is assigned yet
    INSERT INTO public.lesson_assignments (member_id, lesson_code, status, released_by)
    VALUES (p_member_id, '1E', 'Not started', v_uid)
    ON CONFLICT (member_id, lesson_code) DO NOTHING;

    RETURN jsonb_build_object(
        'invitation_id', v_inv_id,
        'member_id', p_member_id,
        'raw_token', v_raw_token,
        'token_prefix', v_prefix,
        'expires_at', v_expires_at
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_issue_invitation(uuid, integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_issue_invitation(uuid, integer) TO authenticated;

-- -----------------------------------------------------------------------------
-- 4. REQUIRE AUTHENTICATED ACCOUNT OWNERSHIP FOR PRIVATE DIRECT MESSAGING
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.learner_send_direct_message(
    p_raw_token text,
    p_recipient_id uuid,
    p_body text,
    p_client_message_id text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_sender_id uuid;
    v_sender_name text;
    v_clean_body text;
    v_clean_msg_id text;
    v_existing RECORD;
    v_dm RECORD;
BEGIN
    -- Require authenticated account ownership for private messaging
    v_uid := auth.uid();
    IF v_uid IS NULL THEN
        RAISE EXCEPTION 'ACCOUNT_REQUIRED: Direct messaging requires a signed-in durable learner account.'
            USING ERRCODE = '28000';
    END IF;

    v_sender_id := public.resolve_learner_identity(p_raw_token);

    IF NOT EXISTS (
        SELECT 1 FROM public.members m
         WHERE m.id = v_sender_id
           AND m.auth_user_id = v_uid
           AND m.interest_status NOT IN ('Not interested', 'Organiser')
    ) THEN
        RAISE EXCEPTION 'ACCOUNT_REQUIRED: Direct messaging requires authenticated account ownership of your learner profile.'
            USING ERRCODE = '42501';
    END IF;

    IF v_sender_id = p_recipient_id THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Cannot send a direct message to yourself.'
            USING ERRCODE = '22023';
    END IF;

    -- 1. Check blocks in either direction
    IF EXISTS (
        SELECT 1 FROM public.member_blocks mb
         WHERE (mb.blocker_id = v_sender_id AND mb.blocked_id = p_recipient_id)
            OR (mb.blocker_id = p_recipient_id AND mb.blocked_id = v_sender_id)
    ) THEN
        RAISE EXCEPTION 'BLOCKED: Direct messaging is unavailable between these profiles.'
            USING ERRCODE = '42501';
    END IF;

    -- 2. Enforce mutual accepted friendship
    IF NOT EXISTS (
        SELECT 1 FROM public.member_friendships mf
         WHERE mf.status = 'accepted'
           AND ((mf.requester_id = v_sender_id AND mf.addressee_id = p_recipient_id)
             OR (mf.requester_id = p_recipient_id AND mf.addressee_id = v_sender_id))
    ) THEN
        RAISE EXCEPTION 'FRIENDS_ONLY: Direct messages can only be sent to accepted club friends.'
            USING ERRCODE = '42501';
    END IF;

    v_clean_body := public.sanitize_club_text(p_body);
    IF char_length(v_clean_body) = 0 OR char_length(v_clean_body) > 2000 THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Message body must be between 1 and 2000 characters.'
            USING ERRCODE = '22023';
    END IF;

    v_clean_msg_id := nullif(trim(coalesce(p_client_message_id, '')), '');

    -- Idempotent retry deduplication by client_message_id
    IF v_clean_msg_id IS NOT NULL THEN
        SELECT * INTO v_existing
          FROM public.direct_messages dm
         WHERE dm.sender_id = v_sender_id
           AND dm.client_message_id = v_clean_msg_id
         LIMIT 1;

        IF FOUND THEN
            RETURN jsonb_build_object(
                'id', v_existing.id,
                'sender_id', v_existing.sender_id,
                'recipient_id', v_existing.recipient_id,
                'body', v_existing.body,
                'client_message_id', v_existing.client_message_id,
                'created_at', v_existing.created_at,
                'deduplicated', true
            );
        END IF;
    END IF;

    SELECT m.name INTO v_sender_name FROM public.members m WHERE m.id = v_sender_id;

    INSERT INTO public.direct_messages (
        sender_id, recipient_id, body, client_message_id, moderation_status
    ) VALUES (
        v_sender_id, p_recipient_id, v_clean_body, v_clean_msg_id, 'visible'
    )
    RETURNING * INTO v_dm;

    INSERT INTO public.member_notifications (member_id, kind, title, body)
    VALUES (
        p_recipient_id,
        'direct_message',
        format('New message from %s', coalesce(v_sender_name, 'Club Friend')),
        left(v_clean_body, 140)
    );

    RETURN jsonb_build_object(
        'id', v_dm.id,
        'sender_id', v_dm.sender_id,
        'sender_name', coalesce(v_sender_name, 'Club Friend'),
        'recipient_id', v_dm.recipient_id,
        'body', v_dm.body,
        'client_message_id', v_dm.client_message_id,
        'created_at', v_dm.created_at,
        'deduplicated', false
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_send_direct_message(text, uuid, text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.learner_send_direct_message(text, uuid, text, text) TO authenticated;

CREATE OR REPLACE FUNCTION public.learner_get_direct_messages(
    p_raw_token text,
    p_partner_id uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_member_id uuid;
    v_messages jsonb;
BEGIN
    -- Require authenticated account ownership for private messaging
    v_uid := auth.uid();
    IF v_uid IS NULL THEN
        RAISE EXCEPTION 'ACCOUNT_REQUIRED: Direct messaging requires a signed-in durable learner account.'
            USING ERRCODE = '28000';
    END IF;

    v_member_id := public.resolve_learner_identity(p_raw_token);

    IF NOT EXISTS (
        SELECT 1 FROM public.members m
         WHERE m.id = v_member_id
           AND m.auth_user_id = v_uid
           AND m.interest_status NOT IN ('Not interested', 'Organiser')
    ) THEN
        RAISE EXCEPTION 'ACCOUNT_REQUIRED: Direct messaging requires authenticated account ownership of your learner profile.'
            USING ERRCODE = '42501';
    END IF;

    IF p_partner_id IS NOT NULL THEN
        UPDATE public.direct_messages
           SET read_at = now(),
               updated_at = now()
         WHERE sender_id = p_partner_id
           AND recipient_id = v_member_id
           AND read_at IS NULL;
    END IF;

    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', dm.id,
            'sender_id', dm.sender_id,
            'sender_name', coalesce(sm.name, 'Club Friend'),
            'recipient_id', dm.recipient_id,
            'recipient_name', coalesce(rm.name, 'Club Friend'),
            'body', dm.body,
            'client_message_id', dm.client_message_id,
            'read_at', dm.read_at,
            'moderation_status', dm.moderation_status,
            'created_at', dm.created_at
        ) ORDER BY dm.created_at ASC
    ), '[]'::jsonb)
    INTO v_messages
    FROM public.direct_messages dm
    LEFT JOIN public.members sm ON sm.id = dm.sender_id
    LEFT JOIN public.members rm ON rm.id = dm.recipient_id
    WHERE (dm.sender_id = v_member_id OR dm.recipient_id = v_member_id)
      AND (p_partner_id IS NULL OR dm.sender_id = p_partner_id OR dm.recipient_id = p_partner_id)
      AND dm.moderation_status <> 'hidden_by_mod'
      AND NOT EXISTS (
          SELECT 1 FROM public.member_blocks mbd
           WHERE (mbd.blocker_id = v_member_id AND mbd.blocked_id = CASE WHEN dm.sender_id = v_member_id THEN dm.recipient_id ELSE dm.sender_id END)
              OR (mbd.blocked_id = v_member_id AND mbd.blocker_id = CASE WHEN dm.sender_id = v_member_id THEN dm.recipient_id ELSE dm.sender_id END)
      );

    RETURN jsonb_build_object(
        'member_id', v_member_id,
        'partner_id', p_partner_id,
        'messages', v_messages
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_get_direct_messages(text, uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.learner_get_direct_messages(text, uuid) TO authenticated;

CREATE OR REPLACE FUNCTION public.learner_report_direct_message(
    p_raw_token text,
    p_message_id uuid,
    p_reason text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_member_id uuid;
    v_clean_reason text;
BEGIN
    -- Require authenticated account ownership for private messaging
    v_uid := auth.uid();
    IF v_uid IS NULL THEN
        RAISE EXCEPTION 'ACCOUNT_REQUIRED: Direct messaging requires a signed-in durable learner account.'
            USING ERRCODE = '28000';
    END IF;

    v_member_id := public.resolve_learner_identity(p_raw_token);

    IF NOT EXISTS (
        SELECT 1 FROM public.members m
         WHERE m.id = v_member_id
           AND m.auth_user_id = v_uid
           AND m.interest_status NOT IN ('Not interested', 'Organiser')
    ) THEN
        RAISE EXCEPTION 'ACCOUNT_REQUIRED: Direct messaging requires authenticated account ownership of your learner profile.'
            USING ERRCODE = '42501';
    END IF;

    v_clean_reason := coalesce(nullif(public.sanitize_club_text(p_reason), ''), 'Reported by conversation participant for steward review');

    -- Only a participant in the conversation can report a direct message
    UPDATE public.direct_messages
       SET moderation_status = 'reported',
           report_reason = v_clean_reason,
           reported_by = v_member_id,
           updated_at = now()
     WHERE id = p_message_id
       AND (recipient_id = v_member_id OR sender_id = v_member_id)
       AND moderation_status <> 'hidden_by_mod';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND: Direct message not found in your conversations.'
            USING ERRCODE = 'P0002';
    END IF;

    RETURN jsonb_build_object('status', 'reported', 'message_id', p_message_id);
END;
$$;

REVOKE ALL ON FUNCTION public.learner_report_direct_message(text, uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.learner_report_direct_message(text, uuid, text) TO authenticated;


-- Updated learner_get_portal with authenticated account ownership gate for direct_messages
CREATE OR REPLACE FUNCTION public.learner_get_portal(p_raw_token text DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_member jsonb;
    v_club_settings jsonb;
    v_catalog jsonb;
    v_assignments jsonb;
    v_mistakes jsonb;
    v_notifications jsonb;
    v_directory jsonb;
    v_friendships jsonb;
    v_posts jsonb;
    v_sessions jsonb;
    v_direct_messages jsonb;
    v_study_groups jsonb;
    v_expires_at timestamptz := NULL;
    v_hash text;
    v_clean_token text;
    v_founders_count integer;
BEGIN
    v_member_id := public.resolve_learner_identity(p_raw_token);
    v_clean_token := lower(trim(coalesce(p_raw_token, '')));

    IF char_length(v_clean_token) >= 32 AND v_clean_token ~ '^[0-9a-f]+$' THEN
        v_hash := encode(extensions.digest(convert_to(v_clean_token, 'UTF8'), 'sha256'), 'hex');
        SELECT li.expires_at INTO v_expires_at
          FROM public.learner_invitations li
         WHERE li.token_hash = v_hash;
    END IF;

    SELECT count(*)::integer INTO v_founders_count
      FROM public.members
     WHERE founder_number IS NOT NULL;

    SELECT jsonb_build_object(
        'id', m.id,
        'name', m.name,
        'experience', m.experience,
        'availability_pkt', m.availability_pkt,
        'auth_linked', (m.auth_user_id IS NOT NULL),
        'email_verified', (m.email_verified_at IS NOT NULL),
        'membership_tier', m.membership_tier,
        'founder_number', m.founder_number,
        'founder_granted_at', m.founder_granted_at,
        'invitation_expires_at', v_expires_at
    )
    INTO v_member
    FROM public.members m
    WHERE m.id = v_member_id;

    SELECT jsonb_build_object(
        'progression_threshold_pct', coalesce(cs.progression_threshold_pct, 80),
        'answer_key_version', coalesce(cs.answer_key_version, 'v3.0-founding100'),
        'founding_100_limit', coalesce(cs.founding_100_limit, 100),
        'founding_100_allocated_count', v_founders_count,
        'founding_100_remaining', greatest(coalesce(cs.founding_100_limit, 100) - v_founders_count, 0),
        'founding_100_benefits_json', coalesce(cs.founding_100_benefits_json, '[]'::jsonb)
    )
    INTO v_club_settings
    FROM public.club_settings cs
    WHERE cs.id = 1;

    -- Public lesson catalog metadata (never exposes lesson_private_materials)
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'code', l.code,
            'seq_order', l.seq_order,
            'title', l.title,
            'subtitle', l.subtitle,
            'objective', l.objective,
            'is_draft', l.is_draft,
            'validation_status', l.validation_status,
            'withheld_hands_json', l.withheld_hands_json,
            'extra_hands_json', l.extra_hands_json,
            'transcription_flags', l.transcription_flags
        ) ORDER BY l.seq_order ASC
    ), '[]'::jsonb)
    INTO v_catalog
    FROM public.lessons l;

    -- Explicitly unlocked/assigned lessons for this learner
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'assignment_id', la.id,
            'lesson_code', la.lesson_code,
            'status', la.status,
            'released_at', la.released_at,
            'finished_at', la.finished_at,
            'lesson', jsonb_build_object(
                'code', l.code,
                'seq_order', l.seq_order,
                'title', l.title,
                'subtitle', l.subtitle,
                'objective', l.objective,
                'instructions', l.instructions,
                'bidding_rules_json', l.bidding_rules_json,
                'hands_json', l.hands_json,
                'withheld_hands_json', l.withheld_hands_json,
                'extra_hands_json', l.extra_hands_json,
                'transcription_flags', l.transcription_flags,
                'is_draft', l.is_draft,
                'validation_status', l.validation_status
            ),
            'submissions', coalesce((
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'id', s.id,
                        'version_number', s.version_number,
                        'status', s.status,
                        'client_request_id', s.client_request_id,
                        'answers_json', s.answers_json,
                        'learner_questions', s.learner_questions,
                        'grading_json', s.grading_json,
                        'created_at', s.created_at,
                        'updated_at', s.updated_at,
                        'submitted_at', s.submitted_at,
                        'reviewed_at', s.reviewed_at,
                        'feedback', coalesce((
                            SELECT jsonb_agg(
                                jsonb_build_object(
                                    'id', sf.id,
                                    'organiser_feedback', sf.organiser_feedback,
                                    'question_resolved', sf.question_resolved,
                                    'created_at', sf.created_at
                                ) ORDER BY sf.created_at ASC
                            )
                            FROM public.submission_feedback sf
                            WHERE sf.submission_id = s.id
                        ), '[]'::jsonb)
                    ) ORDER BY s.version_number DESC
                )
                FROM public.submissions s
                WHERE s.assignment_id = la.id
                  AND s.member_id = v_member_id
            ), '[]'::jsonb)
        ) ORDER BY l.seq_order ASC
    ), '[]'::jsonb)
    INTO v_assignments
    FROM public.lesson_assignments la
    JOIN public.lessons l ON l.code = la.lesson_code
    WHERE la.member_id = v_member_id;

    -- Personal mistake queue
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', mq.id,
            'member_id', mq.member_id,
            'lesson_code', mq.lesson_code,
            'hand_number', mq.hand_number,
            'missed_skills', mq.missed_skills,
            'last_diagnostic', mq.last_diagnostic,
            'times_missed', mq.times_missed,
            'mastered', mq.mastered,
            'updated_at', mq.updated_at
        ) ORDER BY mq.lesson_code ASC, mq.hand_number ASC
    ), '[]'::jsonb)
    INTO v_mistakes
    FROM public.learner_mistake_queue mq
    WHERE mq.member_id = v_member_id;

    -- Personal notifications
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', n.id,
            'member_id', n.member_id,
            'kind', n.kind,
            'title', n.title,
            'body', n.body,
            'is_read', n.is_read,
            'created_at', n.created_at
        ) ORDER BY n.created_at DESC
    ), '[]'::jsonb)
    INTO v_notifications
    FROM public.member_notifications n
    WHERE n.member_id = v_member_id;

    -- Club Member Directory (STRICTLY omits email and private organiser notes!)
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', m.id,
            'name', m.name,
            'experience', m.experience,
            'availability_pkt', m.availability_pkt,
            'membership_tier', m.membership_tier,
            'founder_number', m.founder_number,
            'is_organiser', (m.interest_status = 'Organiser'),
            'is_blocked_by_me', EXISTS (
                SELECT 1 FROM public.member_blocks mb
                 WHERE mb.blocker_id = v_member_id AND mb.blocked_id = m.id
            )
        ) ORDER BY m.created_at ASC
    ), '[]'::jsonb)
    INTO v_directory
    FROM public.members m
    WHERE m.interest_status <> 'Not interested';

    -- Member's friendships
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', mf.id,
            'requester_id', mf.requester_id,
            'addressee_id', mf.addressee_id,
            'status', mf.status,
            'created_at', mf.created_at,
            'updated_at', mf.updated_at
        ) ORDER BY mf.created_at DESC
    ), '[]'::jsonb)
    INTO v_friendships
    FROM public.member_friendships mf
    WHERE mf.requester_id = v_member_id OR mf.addressee_id = v_member_id;

    -- Personal Direct Messages (Requires authenticated account ownership: auth.uid() must own v_member_id)
    IF auth.uid() IS NOT NULL AND EXISTS (
        SELECT 1 FROM public.members m
         WHERE m.id = v_member_id
           AND m.auth_user_id = auth.uid()
    ) THEN
        SELECT coalesce(jsonb_agg(
            jsonb_build_object(
                'id', dm.id,
                'sender_id', dm.sender_id,
                'sender_name', coalesce(sm.name, 'Club Friend'),
                'recipient_id', dm.recipient_id,
                'recipient_name', coalesce(rm.name, 'Club Friend'),
                'body', dm.body,
                'client_message_id', dm.client_message_id,
                'read_at', dm.read_at,
                'moderation_status', dm.moderation_status,
                'created_at', dm.created_at
            ) ORDER BY dm.created_at ASC
        ), '[]'::jsonb)
        INTO v_direct_messages
        FROM public.direct_messages dm
        LEFT JOIN public.members sm ON sm.id = dm.sender_id
        LEFT JOIN public.members rm ON rm.id = dm.recipient_id
        WHERE (dm.sender_id = v_member_id OR dm.recipient_id = v_member_id)
          AND dm.moderation_status <> 'hidden_by_mod'
          AND NOT EXISTS (
              SELECT 1 FROM public.member_blocks mbd
               WHERE (mbd.blocker_id = v_member_id AND mbd.blocked_id = CASE WHEN dm.sender_id = v_member_id THEN dm.recipient_id ELSE dm.sender_id END)
                  OR (mbd.blocked_id = v_member_id AND mbd.blocker_id = CASE WHEN dm.sender_id = v_member_id THEN dm.recipient_id ELSE dm.sender_id END)
          );
    ELSE
        v_direct_messages := '[]'::jsonb;
    END IF;

    -- Study Groups
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', sg.id,
            'creator_id', sg.creator_id,
            'creator_name', coalesce(cm.name, 'Club Member'),
            'name', sg.name,
            'focus_lesson', sg.focus_lesson,
            'description', sg.description,
            'meeting_time_pkt', sg.meeting_time_pkt,
            'created_at', sg.created_at,
            'member_names', coalesce((
                SELECT jsonb_agg(coalesce(gm.name, 'Member') ORDER BY sgm.created_at ASC)
                FROM public.study_group_members sgm
                LEFT JOIN public.members gm ON gm.id = sgm.member_id
                WHERE sgm.group_id = sg.id
            ), '[]'::jsonb),
            'is_member', EXISTS (
                SELECT 1 FROM public.study_group_members sgm2
                 WHERE sgm2.group_id = sg.id AND sgm2.member_id = v_member_id
            )
        ) ORDER BY sg.created_at DESC
    ), '[]'::jsonb)
    INTO v_study_groups
    FROM public.study_groups sg
    LEFT JOIN public.members cm ON cm.id = sg.creator_id;

    -- Visible community posts
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', p.id,
            'author_id', p.author_id,
            'author_name', coalesce(am.name, 'Club Member'),
            'category', p.category,
            'lesson_code', p.lesson_code,
            'title', p.title,
            'body', p.body,
            'moderation_status', p.moderation_status,
            'report_reason', p.report_reason,
            'reported_by', p.reported_by,
            'created_at', p.created_at,
            'comments', coalesce((
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'id', c.id,
                        'post_id', c.post_id,
                        'author_id', c.author_id,
                        'author_name', coalesce(cm.name, 'Club Member'),
                        'body', c.body,
                        'is_organiser_reply', c.is_organiser_reply,
                        'moderation_status', c.moderation_status,
                        'created_at', c.created_at
                    ) ORDER BY c.created_at ASC
                )
                FROM public.community_comments c
                LEFT JOIN public.members cm ON cm.id = c.author_id
                WHERE c.post_id = p.id
                  AND c.moderation_status <> 'hidden_by_mod'
                  AND NOT EXISTS (
                      SELECT 1 FROM public.member_blocks mbc
                       WHERE (mbc.blocker_id = v_member_id AND mbc.blocked_id = c.author_id)
                          OR (mbc.blocker_id = c.author_id AND mbc.blocked_id = v_member_id)
                  )
            ), '[]'::jsonb)
        ) ORDER BY p.created_at DESC
    ), '[]'::jsonb)
    INTO v_posts
    FROM public.community_posts p
    LEFT JOIN public.members am ON am.id = p.author_id
    WHERE p.moderation_status <> 'hidden_by_mod'
      AND NOT EXISTS (
          SELECT 1 FROM public.member_blocks mbp
           WHERE (mbp.blocker_id = v_member_id AND mbp.blocked_id = p.author_id)
              OR (mbp.blocker_id = p.author_id AND mbp.blocked_id = v_member_id)
      );

    -- Practice sessions & RSVPs
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', ps.id,
            'host_id', ps.host_id,
            'host_name', coalesce(hm.name, 'Organiser'),
            'title', ps.title,
            'scheduled_pkt', ps.scheduled_pkt,
            'focus_topic', ps.focus_topic,
            'table_room_note', ps.external_bbo_note,
            'max_players', ps.max_players,
            'created_at', ps.created_at,
            'player_names', coalesce((
                SELECT jsonb_agg(coalesce(rm.name, 'Member') ORDER BY r.created_at ASC)
                FROM public.practice_session_rsvps r
                LEFT JOIN public.members rm ON rm.id = r.member_id
                WHERE r.session_id = ps.id
            ), '[]'::jsonb),
            'is_joined', EXISTS (
                SELECT 1 FROM public.practice_session_rsvps r2
                 WHERE r2.session_id = ps.id AND r2.member_id = v_member_id
            )
        ) ORDER BY ps.created_at DESC
    ), '[]'::jsonb)
    INTO v_sessions
    FROM public.practice_sessions ps
    LEFT JOIN public.members hm ON hm.id = ps.host_id;

    RETURN jsonb_build_object(
        'member', v_member,
        'club_settings', v_club_settings,
        'all_lessons_catalog', v_catalog,
        'assignments', v_assignments,
        'mistake_queue', v_mistakes,
        'notifications', v_notifications,
        'directory', v_directory,
        'friendships', v_friendships,
        'direct_messages', v_direct_messages,
        'study_groups', v_study_groups,
        'community_posts', v_posts,
        'practice_sessions', v_sessions
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_get_portal(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_get_portal(text) TO anon, authenticated;

COMMIT;
