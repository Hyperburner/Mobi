-- =============================================================================
-- BRIDGE LEARNING COMMUNITY PORTAL — SUPABASE POSTGRESQL SCHEMA & RPCs
-- =============================================================================
-- Security properties enforced by this script:
-- 1. Organiser authorisation is tied strictly to Supabase Auth (`auth.users`)
--    via the backend-only `public.organiser_users` allowlist table. No user can
--    self-promote via the API, and no shared passphrase exists.
-- 2. Direct table access (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) is revoked
--    from `PUBLIC`, `anon`, and `authenticated`. Row-Level Security (RLS) is
--    enabled and forced on all tables.
-- 3. Learner invitation credentials use 256-bit cryptographically random tokens
--    (`gen_random_bytes(32)`). Only the SHA-256 hash (`token_hash`) is persisted
--    in `public.learner_invitations`. Tokens expire and can be revoked at any time.
-- 4. Private organiser notes and answer keys live in dedicated tables
--    (`public.lesson_private_materials`, `public.member_private_notes`) that
--    learner RPCs never query or return.
-- 5. Submission history is immutable once submitted: saving a draft updates the
--    current `'draft'` row, while submitting locks that version (`'submitted'`)
--    via a database trigger. Subsequent edits create a new `version_number`.
-- 6. Lesson progression (`1E` -> `1F` -> `1G`) is never automatic. Releasing `1F`
--    or `1G` requires both a `'Reviewed'`/`'Finished'` preceding assignment with
--    a reviewed submission AND an explicit organiser RPC call.
-- =============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

-- -----------------------------------------------------------------------------
-- 1. TABLES
-- -----------------------------------------------------------------------------

-- Backend-enforced allowlist of organiser accounts (linked to Supabase Auth)
CREATE TABLE IF NOT EXISTS public.organiser_users (
    user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Learner-readable lesson definitions (1F and 1G start as empty organiser drafts)
CREATE TABLE IF NOT EXISTS public.lessons (
    code text PRIMARY KEY CHECK (code IN ('1E', '1F', '1G')),
    seq_order integer NOT NULL UNIQUE CHECK (seq_order IN (1, 2, 3)),
    title text NOT NULL,
    subtitle text NOT NULL DEFAULT '',
    instructions text NOT NULL DEFAULT '',
    bidding_rules_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    hands_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    transcription_flags text NOT NULL DEFAULT '',
    is_draft boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Strictly private organiser answer keys and source audit notes (NEVER exposed to learners)
CREATE TABLE IF NOT EXISTS public.lesson_private_materials (
    lesson_code text PRIMARY KEY REFERENCES public.lessons(code) ON DELETE CASCADE,
    answer_key_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    organiser_source_notes text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Community members / learners tracked by the organiser
CREATE TABLE IF NOT EXISTS public.members (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    name text NOT NULL CHECK (char_length(trim(name)) > 0),
    email text,
    interest_status text NOT NULL DEFAULT 'Interested' CHECK (
        interest_status IN (
            'Organiser',
            'Not contacted',
            'Awaiting reply',
            'Interested',
            'Maybe later',
            'Regular',
            'Not interested'
        )
    ),
    availability_pkt text NOT NULL DEFAULT '',
    experience text NOT NULL DEFAULT 'New to bridge' CHECK (
        experience IN (
            'New to bridge',
            'Learning',
            'Comfortable playing',
            'Can help teach'
        )
    ),
    last_emailed_date date,
    follow_up_date date,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Strictly private per-member organiser notes & internal next-action reminders
CREATE TABLE IF NOT EXISTS public.member_private_notes (
    member_id uuid PRIMARY KEY REFERENCES public.members(id) ON DELETE CASCADE,
    organiser_notes text NOT NULL DEFAULT '',
    questions_next_action text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Hashed, expiring, revocable learner invitation credentials
CREATE TABLE IF NOT EXISTS public.learner_invitations (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    member_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE CHECK (char_length(token_hash) = 64),
    token_prefix text NOT NULL CHECK (char_length(token_prefix) <= 12),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    last_used_at timestamptz,
    created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_learner_invitations_member_id
    ON public.learner_invitations(member_id);

-- Per-learner lesson assignments (preserves full timeline across 1E -> 1F -> 1G)
CREATE TABLE IF NOT EXISTS public.lesson_assignments (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    member_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    lesson_code text NOT NULL REFERENCES public.lessons(code) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'Not started' CHECK (
        status IN (
            'Not started',
            'Working on it',
            'Needs help',
            'Submitted',
            'Reviewed',
            'Finished',
            'Paused'
        )
    ),
    released_at timestamptz NOT NULL DEFAULT now(),
    released_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
    finished_at date,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (member_id, lesson_code)
);

CREATE INDEX IF NOT EXISTS idx_lesson_assignments_member_id
    ON public.lesson_assignments(member_id);

-- Versioned learner drafts and submitted work (submitted rows are immutable)
CREATE TABLE IF NOT EXISTS public.submissions (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    assignment_id uuid NOT NULL REFERENCES public.lesson_assignments(id) ON DELETE CASCADE,
    member_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    lesson_code text NOT NULL REFERENCES public.lessons(code) ON DELETE RESTRICT,
    version_number integer NOT NULL CHECK (version_number >= 1),
    status text NOT NULL DEFAULT 'draft' CHECK (
        status IN ('draft', 'submitted', 'reviewed')
    ),
    answers_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    learner_questions text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    submitted_at timestamptz,
    reviewed_at timestamptz,
    UNIQUE (assignment_id, version_number)
);

CREATE INDEX IF NOT EXISTS idx_submissions_assignment_id
    ON public.submissions(assignment_id);

-- Organiser feedback entries linked to specific submission versions
CREATE TABLE IF NOT EXISTS public.submission_feedback (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    submission_id uuid NOT NULL REFERENCES public.submissions(id) ON DELETE CASCADE,
    assignment_id uuid NOT NULL REFERENCES public.lesson_assignments(id) ON DELETE CASCADE,
    member_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    organiser_feedback text NOT NULL,
    question_resolved boolean NOT NULL DEFAULT false,
    created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_submission_feedback_submission_id
    ON public.submission_feedback(submission_id);

-- -----------------------------------------------------------------------------
-- 2. IMMUTABILITY TRIGGER FOR SUBMITTED WORK
-- -----------------------------------------------------------------------------
-- Prevents any update from overwriting answers, questions, version_number, or
-- submitted_at once a submission has left 'draft' status.
CREATE OR REPLACE FUNCTION public.enforce_submission_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF OLD.status IN ('submitted', 'reviewed') THEN
        IF NEW.answers_json IS DISTINCT FROM OLD.answers_json
           OR NEW.learner_questions IS DISTINCT FROM OLD.learner_questions
           OR NEW.version_number IS DISTINCT FROM OLD.version_number
           OR NEW.assignment_id IS DISTINCT FROM OLD.assignment_id
           OR NEW.member_id IS DISTINCT FROM OLD.member_id
           OR NEW.lesson_code IS DISTINCT FROM OLD.lesson_code
           OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at THEN
            RAISE EXCEPTION 'IMMUTABLE_SUBMISSION: Submitted work cannot be overwritten. Create a new revision instead.'
                USING ERRCODE = '42501';
        END IF;
        IF OLD.status = 'reviewed' AND NEW.status <> 'reviewed' THEN
            RAISE EXCEPTION 'IMMUTABLE_SUBMISSION: Reviewed status cannot be reverted.'
                USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_enforce_submission_immutability ON public.submissions;
CREATE TRIGGER trg_enforce_submission_immutability
    BEFORE UPDATE ON public.submissions
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_submission_immutability();

-- -----------------------------------------------------------------------------
-- 3. LOCK DOWN DIRECT TABLE ACCESS & ENABLE ROW-LEVEL SECURITY
-- -----------------------------------------------------------------------------
ALTER TABLE public.organiser_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organiser_users FORCE ROW LEVEL SECURITY;

ALTER TABLE public.lessons ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lessons FORCE ROW LEVEL SECURITY;

ALTER TABLE public.lesson_private_materials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lesson_private_materials FORCE ROW LEVEL SECURITY;

ALTER TABLE public.members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.members FORCE ROW LEVEL SECURITY;

ALTER TABLE public.member_private_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.member_private_notes FORCE ROW LEVEL SECURITY;

ALTER TABLE public.learner_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.learner_invitations FORCE ROW LEVEL SECURITY;

ALTER TABLE public.lesson_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lesson_assignments FORCE ROW LEVEL SECURITY;

ALTER TABLE public.submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.submissions FORCE ROW LEVEL SECURITY;

ALTER TABLE public.submission_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.submission_feedback FORCE ROW LEVEL SECURITY;

-- Revoke all direct table privileges from API roles; all access goes through
-- explicitly permissioned SECURITY DEFINER functions below.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, anon, authenticated;

-- -----------------------------------------------------------------------------
-- 4. INTERNAL AUTHORISATION & TOKEN VALIDATION HELPERS
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.assert_is_organiser()
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
BEGIN
    v_uid := auth.uid();
    IF v_uid IS NULL THEN
        RAISE EXCEPTION 'UNAUTHENTICATED: Please sign in with your Organiser Supabase Auth account.'
            USING ERRCODE = '28000';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.organiser_users ou WHERE ou.user_id = v_uid
    ) THEN
        RAISE EXCEPTION 'FORBIDDEN: Your authenticated account is not authorised in public.organiser_users.'
            USING ERRCODE = '42501';
    END IF;

    RETURN v_uid;
END;
$$;

REVOKE ALL ON FUNCTION public.assert_is_organiser() FROM PUBLIC, anon, authenticated;

-- Validates a raw learner invitation token using SHA-256 hash lookup
CREATE OR REPLACE FUNCTION public.validate_learner_token(p_raw_token text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_clean text;
    v_hash text;
    v_inv RECORD;
    v_member_status text;
BEGIN
    v_clean := lower(trim(coalesce(p_raw_token, '')));
    IF char_length(v_clean) < 32 OR v_clean !~ '^[0-9a-f]+$' THEN
        RAISE EXCEPTION 'INVALID_TOKEN: This invitation link is invalid.'
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

    IF v_inv.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'REVOKED_TOKEN: This invitation link has been revoked by the organiser.'
            USING ERRCODE = '28000';
    END IF;

    IF v_inv.expires_at <= now() THEN
        RAISE EXCEPTION 'EXPIRED_TOKEN: This invitation link has expired. Please ask the organiser for a new link.'
            USING ERRCODE = '28000';
    END IF;

    SELECT m.interest_status INTO v_member_status
      FROM public.members m
     WHERE m.id = v_inv.member_id;

    IF v_member_status IS NULL OR v_member_status = 'Not interested' OR v_member_status = 'Organiser' THEN
        RAISE EXCEPTION 'INACTIVE_LEARNER: This learner profile is not active for lessons.'
            USING ERRCODE = '42501';
    END IF;

    UPDATE public.learner_invitations
       SET last_used_at = now()
     WHERE id = v_inv.id;

    RETURN v_inv.member_id;
END;
$$;

REVOKE ALL ON FUNCTION public.validate_learner_token(text) FROM PUBLIC, anon, authenticated;

-- -----------------------------------------------------------------------------
-- 5. LEARNER RPC FUNCTIONS (Callable by anon & authenticated with valid token)
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.learner_get_portal(p_raw_token text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_member jsonb;
    v_assignments jsonb;
    v_expires_at timestamptz;
    v_hash text;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);
    v_hash := encode(extensions.digest(convert_to(lower(trim(p_raw_token)), 'UTF8'), 'sha256'), 'hex');

    SELECT li.expires_at INTO v_expires_at
      FROM public.learner_invitations li
     WHERE li.token_hash = v_hash;

    SELECT jsonb_build_object(
        'id', m.id,
        'name', m.name,
        'experience', m.experience,
        'availability_pkt', m.availability_pkt,
        'invitation_expires_at', v_expires_at
    )
    INTO v_member
    FROM public.members m
    WHERE m.id = v_member_id;

    -- Fetch ONLY explicitly released lessons for this specific learner,
    -- joining only public.lessons (NEVER lesson_private_materials or member_private_notes)
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
                'instructions', l.instructions,
                'bidding_rules_json', l.bidding_rules_json,
                'hands_json', l.hands_json,
                'transcription_flags', l.transcription_flags,
                'is_draft', l.is_draft
            ),
            'submissions', coalesce((
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'id', s.id,
                        'version_number', s.version_number,
                        'status', s.status,
                        'answers_json', s.answers_json,
                        'learner_questions', s.learner_questions,
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

    RETURN jsonb_build_object(
        'member', v_member,
        'assignments', v_assignments
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_get_portal(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_get_portal(text) TO anon, authenticated;

-- Saves a learner draft without overwriting any previously submitted version
CREATE OR REPLACE FUNCTION public.learner_save_draft(
    p_raw_token text,
    p_lesson_code text,
    p_answers_json jsonb,
    p_learner_questions text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_assignment RECORD;
    v_draft_id uuid;
    v_next_ver integer;
    v_new_status text;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);

    SELECT la.id, la.status
      INTO v_assignment
      FROM public.lesson_assignments la
     WHERE la.member_id = v_member_id
       AND la.lesson_code = p_lesson_code
     LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_ASSIGNED: This lesson has not been released to you.'
            USING ERRCODE = '42501';
    END IF;

    IF v_assignment.status = 'Paused' THEN
        RAISE EXCEPTION 'ASSIGNMENT_PAUSED: This lesson assignment is currently paused.'
            USING ERRCODE = '42501';
    END IF;

    -- Look for an existing mutable 'draft' row for this assignment
    SELECT s.id, s.version_number
      INTO v_draft_id, v_next_ver
      FROM public.submissions s
     WHERE s.assignment_id = v_assignment.id
       AND s.member_id = v_member_id
       AND s.status = 'draft'
     ORDER BY s.version_number DESC
     LIMIT 1;

    IF v_draft_id IS NOT NULL THEN
        UPDATE public.submissions
           SET answers_json = coalesce(p_answers_json, '{}'::jsonb),
               learner_questions = coalesce(p_learner_questions, ''),
               updated_at = now()
         WHERE id = v_draft_id;
    ELSE
        SELECT coalesce(max(s.version_number), 0) + 1
          INTO v_next_ver
          FROM public.submissions s
         WHERE s.assignment_id = v_assignment.id;

        INSERT INTO public.submissions (
            assignment_id,
            member_id,
            lesson_code,
            version_number,
            status,
            answers_json,
            learner_questions
        ) VALUES (
            v_assignment.id,
            v_member_id,
            p_lesson_code,
            v_next_ver,
            'draft',
            coalesce(p_answers_json, '{}'::jsonb),
            coalesce(p_learner_questions, '')
        )
        RETURNING id INTO v_draft_id;
    END IF;

    -- Update assignment status only if not already Reviewed or Finished
    IF v_assignment.status NOT IN ('Reviewed', 'Finished', 'Submitted') THEN
        v_new_status := CASE
            WHEN char_length(trim(coalesce(p_learner_questions, ''))) > 0 THEN 'Needs help'
            ELSE 'Working on it'
        END;
        UPDATE public.lesson_assignments
           SET status = v_new_status,
               updated_at = now()
         WHERE id = v_assignment.id;
    END IF;

    RETURN jsonb_build_object(
        'submission_id', v_draft_id,
        'version_number', v_next_ver,
        'status', 'draft',
        'updated_at', now()
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_save_draft(text, text, jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_save_draft(text, text, jsonb, text) TO anon, authenticated;

-- Submits learner answers/questions as an immutable versioned record
CREATE OR REPLACE FUNCTION public.learner_submit_work(
    p_raw_token text,
    p_lesson_code text,
    p_answers_json jsonb,
    p_learner_questions text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_assignment RECORD;
    v_sub_id uuid;
    v_ver integer;
    v_new_assignment_status text;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);

    SELECT la.id, la.status
      INTO v_assignment
      FROM public.lesson_assignments la
     WHERE la.member_id = v_member_id
       AND la.lesson_code = p_lesson_code
     LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_ASSIGNED: This lesson has not been released to you.'
            USING ERRCODE = '42501';
    END IF;

    IF v_assignment.status = 'Paused' THEN
        RAISE EXCEPTION 'ASSIGNMENT_PAUSED: This lesson assignment is currently paused.'
            USING ERRCODE = '42501';
    END IF;

    -- Check if there is an active draft to finalise into 'submitted'
    SELECT s.id, s.version_number
      INTO v_sub_id, v_ver
      FROM public.submissions s
     WHERE s.assignment_id = v_assignment.id
       AND s.member_id = v_member_id
       AND s.status = 'draft'
     ORDER BY s.version_number DESC
     LIMIT 1;

    IF v_sub_id IS NOT NULL THEN
        UPDATE public.submissions
           SET answers_json = coalesce(p_answers_json, '{}'::jsonb),
               learner_questions = coalesce(p_learner_questions, ''),
               status = 'submitted',
               submitted_at = now(),
               updated_at = now()
         WHERE id = v_sub_id;
    ELSE
        -- Never overwrite a previously submitted/reviewed row; insert a new version
        SELECT coalesce(max(s.version_number), 0) + 1
          INTO v_ver
          FROM public.submissions s
         WHERE s.assignment_id = v_assignment.id;

        INSERT INTO public.submissions (
            assignment_id,
            member_id,
            lesson_code,
            version_number,
            status,
            answers_json,
            learner_questions,
            submitted_at
        ) VALUES (
            v_assignment.id,
            v_member_id,
            p_lesson_code,
            v_ver,
            'submitted',
            coalesce(p_answers_json, '{}'::jsonb),
            coalesce(p_learner_questions, ''),
            now()
        )
        RETURNING id INTO v_sub_id;
    END IF;

    v_new_assignment_status := CASE
        WHEN char_length(trim(coalesce(p_learner_questions, ''))) > 0 THEN 'Needs help'
        ELSE 'Submitted'
    END;

    UPDATE public.lesson_assignments
       SET status = v_new_assignment_status,
           updated_at = now()
     WHERE id = v_assignment.id;

    UPDATE public.members
       SET interest_status = CASE
               WHEN interest_status IN ('Not contacted', 'Awaiting reply') THEN 'Interested'
               ELSE interest_status
           END,
           updated_at = now()
     WHERE id = v_member_id;

    RETURN jsonb_build_object(
        'submission_id', v_sub_id,
        'version_number', v_ver,
        'status', 'submitted',
        'assignment_status', v_new_assignment_status,
        'submitted_at', now()
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_submit_work(text, text, jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_submit_work(text, text, jsonb, text) TO anon, authenticated;

-- -----------------------------------------------------------------------------
-- 6. ORGANISER RPC FUNCTIONS (Restricted to authenticated Organisers only)
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.organiser_check_status()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_email text;
    v_is_org boolean;
BEGIN
    v_uid := auth.uid();
    IF v_uid IS NULL THEN
        RETURN jsonb_build_object('authenticated', false, 'is_organiser', false);
    END IF;

    SELECT EXISTS (SELECT 1 FROM public.organiser_users ou WHERE ou.user_id = v_uid),
           (SELECT ou.email FROM public.organiser_users ou WHERE ou.user_id = v_uid)
      INTO v_is_org, v_email;

    RETURN jsonb_build_object(
        'authenticated', true,
        'user_id', v_uid,
        'is_organiser', coalesce(v_is_org, false),
        'organiser_email', v_email
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_check_status() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_check_status() TO authenticated;

-- Returns the full Organiser Dashboard state including private notes & answer keys
CREATE OR REPLACE FUNCTION public.organiser_get_dashboard()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_members jsonb;
    v_lessons jsonb;
BEGIN
    v_uid := public.assert_is_organiser();

    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'code', l.code,
            'seq_order', l.seq_order,
            'title', l.title,
            'subtitle', l.subtitle,
            'instructions', l.instructions,
            'bidding_rules_json', l.bidding_rules_json,
            'hands_json', l.hands_json,
            'transcription_flags', l.transcription_flags,
            'is_draft', l.is_draft,
            'private_materials', jsonb_build_object(
                'answer_key_json', coalesce(lpm.answer_key_json, '[]'::jsonb),
                'organiser_source_notes', coalesce(lpm.organiser_source_notes, '')
            )
        ) ORDER BY l.seq_order ASC
    ), '[]'::jsonb)
    INTO v_lessons
    FROM public.lessons l
    LEFT JOIN public.lesson_private_materials lpm ON lpm.lesson_code = l.code;

    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', m.id,
            'name', m.name,
            'email', m.email,
            'interest_status', m.interest_status,
            'availability_pkt', m.availability_pkt,
            'experience', m.experience,
            'last_emailed_date', m.last_emailed_date,
            'follow_up_date', m.follow_up_date,
            'follow_up_check', CASE
                WHEN m.interest_status = 'Not interested' THEN 'Closed'
                WHEN m.follow_up_date IS NULL THEN ''
                WHEN m.follow_up_date <= CURRENT_DATE THEN 'Due'
                ELSE 'Scheduled'
            END,
            'organiser_notes', coalesce(mpn.organiser_notes, ''),
            'questions_next_action', coalesce(mpn.questions_next_action, ''),
            'active_invitation', (
                SELECT jsonb_build_object(
                    'id', li.id,
                    'token_prefix', li.token_prefix,
                    'created_at', li.created_at,
                    'expires_at', li.expires_at,
                    'revoked_at', li.revoked_at,
                    'last_used_at', li.last_used_at,
                    'is_active', (li.revoked_at IS NULL AND li.expires_at > now())
                )
                FROM public.learner_invitations li
                WHERE li.member_id = m.id
                ORDER BY li.created_at DESC
                LIMIT 1
            ),
            'assignments', coalesce((
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'id', la.id,
                        'lesson_code', la.lesson_code,
                        'status', la.status,
                        'released_at', la.released_at,
                        'finished_at', la.finished_at,
                        'submissions', coalesce((
                            SELECT jsonb_agg(
                                jsonb_build_object(
                                    'id', s.id,
                                    'version_number', s.version_number,
                                    'status', s.status,
                                    'answers_json', s.answers_json,
                                    'learner_questions', s.learner_questions,
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
                        ), '[]'::jsonb)
                    ) ORDER BY (
                        CASE la.lesson_code WHEN '1E' THEN 1 WHEN '1F' THEN 2 WHEN '1G' THEN 3 ELSE 9 END
                    ) ASC
                )
                FROM public.lesson_assignments la
                WHERE la.member_id = m.id
            ), '[]'::jsonb)
        ) ORDER BY (CASE WHEN m.interest_status = 'Organiser' THEN 0 ELSE 1 END), m.created_at ASC
    ), '[]'::jsonb)
    INTO v_members
    FROM public.members m
    LEFT JOIN public.member_private_notes mpn ON mpn.member_id = m.id;

    RETURN jsonb_build_object(
        'organiser_uid', v_uid,
        'lessons', v_lessons,
        'members', v_members
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_get_dashboard() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_get_dashboard() TO authenticated;

-- Create or update a member and their private organiser notes
CREATE OR REPLACE FUNCTION public.organiser_upsert_member(
    p_member_id uuid DEFAULT NULL,
    p_name text DEFAULT '',
    p_email text DEFAULT NULL,
    p_interest_status text DEFAULT 'Interested',
    p_availability_pkt text DEFAULT '',
    p_experience text DEFAULT 'New to bridge',
    p_last_emailed_date date DEFAULT NULL,
    p_follow_up_date date DEFAULT NULL,
    p_organiser_notes text DEFAULT '',
    p_questions_next_action text DEFAULT '',
    p_assign_lesson_1e boolean DEFAULT false
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_id uuid;
BEGIN
    v_uid := public.assert_is_organiser();

    IF char_length(trim(coalesce(p_name, ''))) = 0 THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Member name is required.'
            USING ERRCODE = '22023';
    END IF;

    IF p_member_id IS NULL THEN
        INSERT INTO public.members (
            name, email, interest_status, availability_pkt, experience,
            last_emailed_date, follow_up_date
        ) VALUES (
            trim(p_name), nullif(trim(coalesce(p_email, '')), ''), p_interest_status,
            coalesce(p_availability_pkt, ''), p_experience,
            p_last_emailed_date, p_follow_up_date
        )
        RETURNING id INTO v_id;
    ELSE
        UPDATE public.members
           SET name = trim(p_name),
               email = nullif(trim(coalesce(p_email, '')), ''),
               interest_status = p_interest_status,
               availability_pkt = coalesce(p_availability_pkt, ''),
               experience = p_experience,
               last_emailed_date = p_last_emailed_date,
               follow_up_date = p_follow_up_date,
               updated_at = now()
         WHERE id = p_member_id
        RETURNING id INTO v_id;

        IF v_id IS NULL THEN
            RAISE EXCEPTION 'NOT_FOUND: Member record not found.'
                USING ERRCODE = 'P0002';
        END IF;
    END IF;

    INSERT INTO public.member_private_notes (
        member_id, organiser_notes, questions_next_action, updated_at
    ) VALUES (
        v_id, coalesce(p_organiser_notes, ''), coalesce(p_questions_next_action, ''), now()
    )
    ON CONFLICT (member_id) DO UPDATE
       SET organiser_notes = EXCLUDED.organiser_notes,
           questions_next_action = EXCLUDED.questions_next_action,
           updated_at = now();

    IF p_assign_lesson_1e AND p_interest_status <> 'Organiser' THEN
        INSERT INTO public.lesson_assignments (member_id, lesson_code, status, released_by)
        VALUES (v_id, '1E', 'Not started', v_uid)
        ON CONFLICT (member_id, lesson_code) DO NOTHING;
    END IF;

    RETURN jsonb_build_object('member_id', v_id, 'status', 'ok');
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_upsert_member(uuid, text, text, text, text, text, date, date, text, text, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_upsert_member(uuid, text, text, text, text, text, date, date, text, text, boolean) TO authenticated;

-- Generates a new 256-bit cryptographically random invitation token,
-- revokes any previous active token for that member, stores ONLY the SHA-256 hash,
-- and returns the raw token ONCE for the organiser to copy.
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

    IF NOT EXISTS (SELECT 1 FROM public.members WHERE id = p_member_id AND interest_status <> 'Organiser') THEN
        RAISE EXCEPTION 'NOT_FOUND: Valid learner record not found.'
            USING ERRCODE = 'P0002';
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

-- Explicitly revokes all active invitation links for a member
CREATE OR REPLACE FUNCTION public.organiser_revoke_invitation(p_member_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_count integer;
BEGIN
    v_uid := public.assert_is_organiser();

    UPDATE public.learner_invitations
       SET revoked_at = now()
     WHERE member_id = p_member_id
       AND revoked_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN jsonb_build_object('revoked_count', v_count, 'revoked_at', now());
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_revoke_invitation(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_revoke_invitation(uuid) TO authenticated;

-- Organiser reviews a specific learner submission version, records feedback,
-- and updates the assignment status ('Working on it', 'Needs help', 'Reviewed', or 'Finished').
CREATE OR REPLACE FUNCTION public.organiser_review_submission(
    p_submission_id uuid,
    p_feedback text,
    p_question_resolved boolean DEFAULT true,
    p_assignment_status text DEFAULT 'Reviewed'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_sub RECORD;
    v_fb_id uuid;
BEGIN
    v_uid := public.assert_is_organiser();

    IF char_length(trim(coalesce(p_feedback, ''))) = 0 THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Feedback text cannot be empty.'
            USING ERRCODE = '22023';
    END IF;

    IF p_assignment_status NOT IN ('Working on it', 'Needs help', 'Reviewed', 'Finished', 'Paused') THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Invalid assignment review status.'
            USING ERRCODE = '22023';
    END IF;

    SELECT s.id, s.assignment_id, s.member_id, s.status
      INTO v_sub
      FROM public.submissions s
     WHERE s.id = p_submission_id
     LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND: Submission not found.'
            USING ERRCODE = 'P0002';
    END IF;

    IF v_sub.status = 'draft' THEN
        RAISE EXCEPTION 'INVALID_STATE: Cannot formally review an unsubmitted learner draft.'
            USING ERRCODE = '22023';
    END IF;

    UPDATE public.submissions
       SET status = 'reviewed',
           reviewed_at = now(),
           updated_at = now()
     WHERE id = p_submission_id;

    INSERT INTO public.submission_feedback (
        submission_id, assignment_id, member_id, organiser_feedback, question_resolved, created_by
    ) VALUES (
        v_sub.id, v_sub.assignment_id, v_sub.member_id, trim(p_feedback), coalesce(p_question_resolved, true), v_uid
    )
    RETURNING id INTO v_fb_id;

    UPDATE public.lesson_assignments
       SET status = p_assignment_status,
           finished_at = CASE
               WHEN p_assignment_status = 'Finished' THEN coalesce(finished_at, CURRENT_DATE)
               ELSE finished_at
           END,
           updated_at = now()
     WHERE id = v_sub.assignment_id;

    RETURN jsonb_build_object(
        'feedback_id', v_fb_id,
        'submission_id', p_submission_id,
        'assignment_status', p_assignment_status,
        'reviewed_at', now()
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_review_submission(uuid, text, boolean, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_review_submission(uuid, text, boolean, text) TO authenticated;

-- Explicitly releases the next lesson (1E -> 1F -> 1G) ONLY when:
-- 1. Invoked explicitly by an authenticated organiser, AND
-- 2. For 1F or 1G, the preceding lesson ('1E' or '1F') has been reviewed
--    (assignment status IN ('Reviewed', 'Finished') AND at least one submission
--    for the preceding lesson has status = 'reviewed').
CREATE OR REPLACE FUNCTION public.organiser_release_lesson(
    p_member_id uuid,
    p_lesson_code text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_target_lesson RECORD;
    v_prev_code text;
    v_prev_assignment RECORD;
    v_has_reviewed_sub boolean;
    v_assignment_id uuid;
BEGIN
    v_uid := public.assert_is_organiser();

    IF p_lesson_code NOT IN ('1E', '1F', '1G') THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Invalid lesson code %. Must be 1E, 1F, or 1G.', p_lesson_code
            USING ERRCODE = '22023';
    END IF;

    -- Enforce target-lesson readiness: reject draft or empty lessons
    SELECT l.code, l.is_draft, l.hands_json, l.instructions
      INTO v_target_lesson
      FROM public.lessons l
     WHERE l.code = p_lesson_code
     LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND: Target lesson % does not exist.', p_lesson_code
            USING ERRCODE = 'P0002';
    END IF;

    IF v_target_lesson.is_draft IS TRUE THEN
        RAISE EXCEPTION 'LESSON_NOT_READY: Cannot release Lesson % because it is still marked as an organiser-only draft (is_draft = true). Populate and publish the lesson first.', p_lesson_code
            USING ERRCODE = '22023';
    END IF;

    IF jsonb_typeof(v_target_lesson.hands_json) <> 'array'
       OR jsonb_array_length(v_target_lesson.hands_json) = 0
       OR char_length(trim(coalesce(v_target_lesson.instructions, ''))) = 0 THEN
        RAISE EXCEPTION 'LESSON_EMPTY: Cannot release Lesson % because it has no usable exercise hands or instructions.', p_lesson_code
            USING ERRCODE = '22023';
    END IF;

    IF p_lesson_code = '1F' THEN
        v_prev_code := '1E';
    ELSIF p_lesson_code = '1G' THEN
        v_prev_code := '1F';
    ELSE
        v_prev_code := NULL;
    END IF;

    IF v_prev_code IS NOT NULL THEN
        SELECT la.id, la.status
          INTO v_prev_assignment
          FROM public.lesson_assignments la
         WHERE la.member_id = p_member_id
           AND la.lesson_code = v_prev_code
         LIMIT 1;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'PREREQUISITE_NOT_MET: Cannot release Lesson % before Lesson % has been assigned.', p_lesson_code, v_prev_code
                USING ERRCODE = '22023';
        END IF;

        IF v_prev_assignment.status NOT IN ('Reviewed', 'Finished') THEN
            RAISE EXCEPTION 'PREREQUISITE_NOT_MET: Cannot release Lesson % until Lesson % has been reviewed (current status: %).',
                p_lesson_code, v_prev_code, v_prev_assignment.status
                USING ERRCODE = '22023';
        END IF;

        SELECT EXISTS (
            SELECT 1
              FROM public.submissions s
             WHERE s.assignment_id = v_prev_assignment.id
               AND s.status = 'reviewed'
               AND s.reviewed_at IS NOT NULL
        ) INTO v_has_reviewed_sub;

        IF NOT v_has_reviewed_sub THEN
            RAISE EXCEPTION 'PREREQUISITE_NOT_MET: Cannot release Lesson % until at least one learner submission for Lesson % has been reviewed.',
                p_lesson_code, v_prev_code
                USING ERRCODE = '22023';
        END IF;

        -- Mark the preceding lesson as Finished if it was in 'Reviewed' state
        UPDATE public.lesson_assignments
           SET status = 'Finished',
               finished_at = coalesce(finished_at, CURRENT_DATE),
               updated_at = now()
         WHERE id = v_prev_assignment.id;
    END IF;

    INSERT INTO public.lesson_assignments (
        member_id, lesson_code, status, released_at, released_by
    ) VALUES (
        p_member_id, p_lesson_code, 'Not started', now(), v_uid
    )
    ON CONFLICT (member_id, lesson_code) DO UPDATE
       SET updated_at = now()
    RETURNING id INTO v_assignment_id;

    RETURN jsonb_build_object(
        'assignment_id', v_assignment_id,
        'member_id', p_member_id,
        'lesson_code', p_lesson_code,
        'status', 'Not started',
        'released_at', now()
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_release_lesson(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_release_lesson(uuid, text) TO authenticated;

-- Organiser function to update lesson drafts (e.g. populating 1F/1G when ready) or private notes
CREATE OR REPLACE FUNCTION public.organiser_update_lesson_material(
    p_lesson_code text,
    p_title text,
    p_subtitle text,
    p_instructions text,
    p_hands_json jsonb,
    p_is_draft boolean,
    p_answer_key_json jsonb,
    p_organiser_source_notes text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_final_hands jsonb;
    v_final_instr text;
    v_final_draft boolean;
BEGIN
    v_uid := public.assert_is_organiser();

    SELECT coalesce(p_hands_json, l.hands_json),
           coalesce(p_instructions, l.instructions),
           coalesce(p_is_draft, l.is_draft)
      INTO v_final_hands, v_final_instr, v_final_draft
      FROM public.lessons l
     WHERE l.code = p_lesson_code;

    IF v_final_draft IS FALSE THEN
        IF jsonb_typeof(v_final_hands) <> 'array'
           OR jsonb_array_length(v_final_hands) = 0
           OR char_length(trim(coalesce(v_final_instr, ''))) = 0 THEN
            RAISE EXCEPTION 'LESSON_EMPTY: Cannot publish Lesson % (is_draft = false) while hands or instructions are empty.', p_lesson_code
                USING ERRCODE = '22023';
        END IF;
    END IF;

    UPDATE public.lessons
       SET title = coalesce(p_title, title),
           subtitle = coalesce(p_subtitle, subtitle),
           instructions = coalesce(p_instructions, instructions),
           hands_json = coalesce(p_hands_json, hands_json),
           is_draft = coalesce(p_is_draft, is_draft),
           updated_at = now()
     WHERE code = p_lesson_code;

    INSERT INTO public.lesson_private_materials (
        lesson_code, answer_key_json, organiser_source_notes, updated_at
    ) VALUES (
        p_lesson_code, coalesce(p_answer_key_json, '[]'::jsonb), coalesce(p_organiser_source_notes, ''), now()
    )
    ON CONFLICT (lesson_code) DO UPDATE
       SET answer_key_json = EXCLUDED.answer_key_json,
           organiser_source_notes = EXCLUDED.organiser_source_notes,
           updated_at = now();

    RETURN jsonb_build_object('lesson_code', p_lesson_code, 'updated_at', now());
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_update_lesson_material(text, text, text, text, jsonb, boolean, jsonb, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_update_lesson_material(text, text, text, text, jsonb, boolean, jsonb, text) TO authenticated;

-- -----------------------------------------------------------------------------
-- 7. SEED DATA: LESSON 1E (FIRST 6 HANDS) + EMPTY DRAFTS FOR 1F & 1G
-- -----------------------------------------------------------------------------

INSERT INTO public.lessons (
    code, seq_order, title, subtitle, instructions, bidding_rules_json, hands_json, transcription_flags, is_draft
) VALUES (
    '1E',
    1,
    'Lesson 1E: Five Card Major Bidding (American Standard)',
    'Responding to Partner''s 1♥ Opening (First Six Hands)',
    'Using the High Card Points (HCP) and distribution Total Card Points (TCP) rules below, write how many TCP you have and what you would bid in response to your partner''s opening bid of 1♥. Attempt the first six hands only.',
    '[
        {"category": "High Card Points (HCP)", "rule": "Ace (A) = 4 HCP, King (K) = 3 HCP, Queen (Q) = 2 HCP, Jack (J) = 1 HCP, small card (*) = 0 HCP"},
        {"category": "When to Count Distribution (TCP)", "rule": "Count distribution points (TCP) when you have a fit (at least 8 cards in the suit between you). Partner''s 1♥ opening promises at least 5 hearts, so 3+ hearts in your hand guarantees a heart fit."},
        {"category": "Distribution Regime", "rule": "Void (0 cards in a suit) = 5 TCP | Singleton (1 card) = 3 TCP | Doubleton (2 cards) = 1 TCP"},
        {"category": "Responses to Partner''s 1♥", "rule": "Pass = < 6 points | 2♥ = 3+ ♥ and 6–9 TCP | 3♥ = 3+ ♥ and 10–12 TCP | 4♥ = 3+ ♥ and 13–17 TCP"}
    ]'::jsonb,
    '[
        {
            "hand_number": 1,
            "label": "Hand 1 (Row 1, Column 1)",
            "spades": "A * * *",
            "hearts": "A * * *",
            "diamonds": "* *",
            "clubs": "* * *",
            "card_count": 13,
            "source_note": "Suit symbols (♠ ♥ ♦ ♣) explicitly present in Lesson 1E.docx; Hearts line spaced as ''A *  * *'' (4 cards)."
        },
        {
            "hand_number": 2,
            "label": "Hand 2 (Row 1, Column 2)",
            "spades": "K * * *",
            "hearts": "K Q *",
            "diamonds": "K *",
            "clubs": "* * * *",
            "card_count": 13,
            "source_note": "Suit symbols omitted in source .docx cell; suits assigned by standard 4-line order (♠, ♥, ♦, ♣)."
        },
        {
            "hand_number": 3,
            "label": "Hand 3 (Row 1, Column 3)",
            "spades": "* * *",
            "hearts": "K * * *",
            "diamonds": "* * * *",
            "clubs": "* *",
            "card_count": 13,
            "source_note": "Suit symbols omitted in source .docx cell; Hearts line printed as ''K ** *'' (missing space between two small-card asterisks; verified as 4 cards so hand totals 13 cards)."
        },
        {
            "hand_number": 4,
            "label": "Hand 4 (Row 1, Column 4)",
            "spades": "A * *",
            "hearts": "K Q * * *",
            "diamonds": "* * *",
            "clubs": "K Q",
            "card_count": 13,
            "source_note": "Suit symbols omitted in source .docx cell; suits assigned by standard 4-line order (♠, ♥, ♦, ♣)."
        },
        {
            "hand_number": 5,
            "label": "Hand 5 (Row 2, Column 1)",
            "spades": "* * *",
            "hearts": "K * *",
            "diamonds": "J * * *",
            "clubs": "* * *",
            "card_count": 13,
            "source_note": "Suit symbols omitted in source .docx cell; suits assigned by standard 4-line order (♠, ♥, ♦, ♣)."
        },
        {
            "hand_number": 6,
            "label": "Hand 6 (Row 2, Column 2)",
            "spades": "A * *",
            "hearts": "K * *",
            "diamonds": "* * *",
            "clubs": "Q * * *",
            "card_count": 13,
            "source_note": "Suit symbols omitted in source .docx cell; suits assigned by standard 4-line order (♠, ♥, ♦, ♣)."
        }
    ]'::jsonb,
    'Document verification flags from Lesson 1E.docx: (1) The 3x4 grid in Lesson 1E.docx is unnumbered; Hands 1–6 are taken in standard row-major reading order (Row 1 Columns 1–4, then Row 2 Columns 1–2), where all six hands contain exactly 13 cards. (2) Only Hand 1 (Row 1, Col 1) contains explicit ♠ ♥ ♦ ♣ characters in the .docx XML (formatted in Segoe UI Symbol); Hands 2–6 omit the suit icons and rely on positional lines 1–4 for ♠, ♥, ♦, ♣. (3) In Hand 3 (Row 1, Col 3), the second line (Hearts) is typed as "K ** *" without a space between the first two asterisks (1 King + 3 small cards = 4 hearts, giving 13 cards total). (4) Hands 7–12 are withheld as instructed because Hand 7 (Row 2, Col 3) and Hand 9 (Row 3, Col 1) have 14 cards, and Hand 12 (Row 3, Col 4) has 12 cards.',
    false
),
(
    '1F',
    2,
    'Lesson 1F (Organiser Draft — Not Yet Populated)',
    'Awaiting source material audit before release',
    '',
    '[]'::jsonb,
    '[]'::jsonb,
    'Empty organiser-only draft entry. Do not release until Lesson 1F.docx source issues are resolved and content is added.',
    true
),
(
    '1G',
    3,
    'Lesson 1G (Organiser Draft — Not Yet Populated)',
    'Awaiting source material audit before release',
    '',
    '[]'::jsonb,
    '[]'::jsonb,
    'Empty organiser-only draft entry. Do not release until Lesson 1G.docx source issues are resolved and content is added.',
    true
)
ON CONFLICT (code) DO UPDATE
   SET title = EXCLUDED.title,
       subtitle = EXCLUDED.subtitle,
       instructions = EXCLUDED.instructions,
       bidding_rules_json = EXCLUDED.bidding_rules_json,
       hands_json = EXCLUDED.hands_json,
       transcription_flags = EXCLUDED.transcription_flags,
       is_draft = EXCLUDED.is_draft,
       updated_at = now();

-- Private organiser materials (stored strictly in DB, never in index.html)
INSERT INTO public.lesson_private_materials (
    lesson_code, answer_key_json, organiser_source_notes
) VALUES (
    '1E',
    '[
        {"hand_number": 1, "hcp": 8, "dist_pts": 1, "tcp": 9, "recommended_bid": "2♥", "notes": "♠A(4) + ♥A(4) = 8 HCP. 4-card ♥ support (fit). Doubleton ♦ (* *) = +1 TCP -> 9 TCP total -> 2♥ (6–9 TCP)."},
        {"hand_number": 2, "hcp": 11, "dist_pts": 1, "tcp": 12, "recommended_bid": "3♥", "notes": "♠K(3) + ♥KQ(5) + ♦K(3) = 11 HCP. 3-card ♥ support (fit). Doubleton ♦ (K *) = +1 TCP -> 12 TCP total -> 3♥ (10–12 TCP)."},
        {"hand_number": 3, "hcp": 3, "dist_pts": 1, "tcp": 4, "recommended_bid": "Pass", "notes": "♥K(3) = 3 HCP. 4-card ♥ support (fit). Doubleton ♣ (* *) = +1 TCP -> 4 TCP total (< 6 points) -> Pass."},
        {"hand_number": 4, "hcp": 14, "dist_pts": 1, "tcp": 15, "recommended_bid": "4♥", "notes": "♠A(4) + ♥KQ(5) + ♣KQ(5) = 14 HCP. 5-card ♥ support (fit). Doubleton ♣ (K Q) = +1 TCP -> 15 TCP total -> 4♥ (13–17 TCP)."},
        {"hand_number": 5, "hcp": 4, "dist_pts": 0, "tcp": 4, "recommended_bid": "Pass", "notes": "♥K(3) + ♦J(1) = 4 HCP. 3-3-4-3 flat shape = 0 distribution points -> 4 TCP total (< 6 points) -> Pass."},
        {"hand_number": 6, "hcp": 9, "dist_pts": 0, "tcp": 9, "recommended_bid": "2♥", "notes": "♠A(4) + ♥K(3) + ♣Q(2) = 9 HCP. 3-3-3-4 flat shape = 0 distribution points -> 9 TCP total -> 2♥ (6–9 TCP)."}
    ]'::jsonb,
    'PRIVATE ORGANISER AUDIT NOTES (Lesson 1E.docx): Hands 1–6 (Row 1 Cols 1–4, Row 2 Cols 1–2) all have 13 cards. Hands 7–12 in the bottom half of the .docx table have card-count defects in the source file: Hand 7 (R2C3: 4-3-3-4 = 14 cards), Hand 9 (R3C1: 3-4-3-4 = 14 cards), and Hand 12 (R3C4: 1-4-4-3 = 12 cards). Also note whether your group counts +1 doubleton TCP on Qx/Kx/KQx or only small doubletons—the sheet rule states broadly "Doubleton = 1 TCP" when holding a 3+♥ fit.'
),
(
    '1F',
    '[]'::jsonb,
    'PRIVATE ORGANISER NOTE: Lesson 1F.docx has not been audited or uploaded yet. Resolve flagged source issues before populating and releasing.'
),
(
    '1G',
    '[]'::jsonb,
    'PRIVATE ORGANISER NOTE: Lesson 1G.docx has not been audited or uploaded yet. Resolve flagged source issues before populating and releasing.'
)
ON CONFLICT (lesson_code) DO UPDATE
   SET answer_key_json = EXCLUDED.answer_key_json,
       organiser_source_notes = EXCLUDED.organiser_source_notes,
       updated_at = now();

COMMIT;


-- =============================================================================
-- MIGRATION V2: AUTOMATED BEGINNER ACADEMY, DETERMINISTIC BACKEND GRADING,
-- SKILL & MISTAKE TRACKING, GUIDED PLAY, COMMUNITY & EXCEPTION MODERATION
-- =============================================================================
-- Safe, idempotent migration preserving all v1 tables, learner records,
-- assignments, and submission history while adding full live persistence for:
-- - Deterministic lesson grading (`public.learner_submit_and_grade_lesson`)
-- - Single-hand practice & mistake-queue mastery (`public.learner_check_practice_hand`)
-- - Complete portal state (`public.learner_get_portal`, `public.organiser_get_dashboard`)
-- - Learner profile updates (`public.learner_update_profile`)
-- - Friendships & user blocking (`public.learner_manage_friendship`)
-- - Community discussion posts, replies & reporting (`public.learner_create_post`,
--   `public.learner_add_comment`, `public.learner_report_post`)
-- - Practice session scheduling & capacity-checked RSVPs (`public.learner_manage_session`)
-- - In-app notifications (`public.learner_mark_notifications_read`)
-- - Organiser post moderation & progression threshold (`public.organiser_moderate_post`,
--   `public.organiser_update_threshold`)
-- =============================================================================

BEGIN;

-- 1. Club-wide configuration table (organiser-configurable progression threshold)
CREATE TABLE IF NOT EXISTS public.club_settings (
    id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    progression_threshold_pct integer NOT NULL DEFAULT 80 CHECK (progression_threshold_pct BETWEEN 50 AND 100),
    answer_key_version text NOT NULL DEFAULT 'v2.0-2026-10-27',
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.club_settings (id, progression_threshold_pct, answer_key_version)
VALUES (1, 80, 'v2.0-2026-10-27')
ON CONFLICT (id) DO NOTHING;

-- 2. Extend public.lessons, public.lesson_private_materials, and public.submissions non-destructively
ALTER TABLE public.lessons
    ADD COLUMN IF NOT EXISTS validation_status text NOT NULL DEFAULT 'draft'
        CHECK (validation_status IN ('validated', 'awaiting_source_resolution', 'draft')),
    ADD COLUMN IF NOT EXISTS withheld_hands_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS extra_hands_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS objective text NOT NULL DEFAULT '';

ALTER TABLE public.lesson_private_materials
    ADD COLUMN IF NOT EXISTS extra_answer_key_json jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE public.submissions
    ADD COLUMN IF NOT EXISTS grading_json jsonb DEFAULT NULL;

-- 3. Personal "Practice Again" Mistake Queue (tracks per-hand errors by skill)
CREATE TABLE IF NOT EXISTS public.learner_mistake_queue (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    member_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    lesson_code text NOT NULL REFERENCES public.lessons(code) ON DELETE CASCADE,
    hand_number integer NOT NULL,
    missed_skills jsonb NOT NULL DEFAULT '[]'::jsonb,
    last_diagnostic text NOT NULL DEFAULT '',
    times_missed integer NOT NULL DEFAULT 1,
    mastered boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (member_id, lesson_code, hand_number)
);

-- 4. Community Tables: Friendships, Blocks, Posts, Comments, Practice Sessions, Notifications
CREATE TABLE IF NOT EXISTS public.member_friendships (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    requester_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    addressee_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (requester_id <> addressee_id),
    UNIQUE (requester_id, addressee_id)
);

CREATE TABLE IF NOT EXISTS public.member_blocks (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    blocker_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    blocked_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (blocker_id <> blocked_id),
    UNIQUE (blocker_id, blocked_id)
);

CREATE TABLE IF NOT EXISTS public.community_posts (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    author_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    category text NOT NULL DEFAULT 'General' CHECK (category IN ('General', 'Lesson Question', 'Practice Arrangement', 'Club Announcement')),
    lesson_code text REFERENCES public.lessons(code) ON DELETE SET NULL,
    title text NOT NULL CHECK (char_length(trim(title)) BETWEEN 1 AND 160),
    body text NOT NULL CHECK (char_length(trim(body)) BETWEEN 1 AND 2000),
    moderation_status text NOT NULL DEFAULT 'visible' CHECK (moderation_status IN ('visible', 'reported', 'hidden_by_mod')),
    report_reason text NOT NULL DEFAULT '',
    reported_by uuid REFERENCES public.members(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.community_comments (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    post_id uuid NOT NULL REFERENCES public.community_posts(id) ON DELETE CASCADE,
    author_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    body text NOT NULL CHECK (char_length(trim(body)) BETWEEN 1 AND 1200),
    is_organiser_reply boolean NOT NULL DEFAULT false,
    moderation_status text NOT NULL DEFAULT 'visible' CHECK (moderation_status IN ('visible', 'reported', 'hidden_by_mod')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.practice_sessions (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    host_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    title text NOT NULL CHECK (char_length(trim(title)) BETWEEN 1 AND 140),
    scheduled_pkt text NOT NULL,
    focus_topic text NOT NULL DEFAULT 'Lesson 1E & 1F Practice',
    external_bbo_note text NOT NULL DEFAULT 'Lahore Bridge Club In-App Table & Voice Room',
    max_players integer NOT NULL DEFAULT 4 CHECK (max_players BETWEEN 2 AND 16),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.practice_session_rsvps (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    session_id uuid NOT NULL REFERENCES public.practice_sessions(id) ON DELETE CASCADE,
    member_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (session_id, member_id)
);

CREATE TABLE IF NOT EXISTS public.member_notifications (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    member_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    kind text NOT NULL DEFAULT 'info',
    title text NOT NULL,
    body text NOT NULL DEFAULT '',
    is_read boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Enable and Force RLS on all new tables; revoke direct access from anon/authenticated
ALTER TABLE public.club_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.club_settings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.learner_mistake_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.learner_mistake_queue FORCE ROW LEVEL SECURITY;
ALTER TABLE public.member_friendships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.member_friendships FORCE ROW LEVEL SECURITY;
ALTER TABLE public.member_blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.member_blocks FORCE ROW LEVEL SECURITY;
ALTER TABLE public.community_posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.community_posts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.community_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.community_comments FORCE ROW LEVEL SECURITY;
ALTER TABLE public.practice_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.practice_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.practice_session_rsvps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.practice_session_rsvps FORCE ROW LEVEL SECURITY;
ALTER TABLE public.member_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.member_notifications FORCE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, anon, authenticated;

-- Text sanitizer helper (strips <script> tags and inline event attributes)
CREATE OR REPLACE FUNCTION public.sanitize_club_text(p_input text)
RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = public, pg_temp
AS $$
    SELECT trim(
        regexp_replace(
            regexp_replace(coalesce(p_input, ''), '<\s*\/?\s*script\b[^>]*>', '', 'gi'),
            '\bon[a-zA-Z]+\s*=', '', 'gi'
        )
    );
$$;

REVOKE ALL ON FUNCTION public.sanitize_club_text(text) FROM PUBLIC, anon, authenticated;

-- Update immutability trigger so grading_json cannot be tampered with once submitted
CREATE OR REPLACE FUNCTION public.enforce_submission_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF OLD.status IN ('submitted', 'reviewed') THEN
        IF NEW.answers_json IS DISTINCT FROM OLD.answers_json
           OR NEW.learner_questions IS DISTINCT FROM OLD.learner_questions
           OR NEW.version_number IS DISTINCT FROM OLD.version_number
           OR NEW.assignment_id IS DISTINCT FROM OLD.assignment_id
           OR NEW.member_id IS DISTINCT FROM OLD.member_id
           OR NEW.lesson_code IS DISTINCT FROM OLD.lesson_code
           OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at
           OR (OLD.grading_json IS NOT NULL AND NEW.grading_json IS DISTINCT FROM OLD.grading_json) THEN
            RAISE EXCEPTION 'IMMUTABLE_SUBMISSION: Submitted work and backend grading cannot be overwritten. Submit a new attempt version instead.'
                USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

-- 5. Seed Validated Lesson 1E (6 core + 3 extra hands + 3 withheld) & Validated Lesson 1F (10 hands + 2 withheld) & Locked Lesson 1G
UPDATE public.lessons
   SET objective = 'Count High Card Points (HCP) and 5-3-1 short-suit distribution points with an 8+ card heart fit, then choose the right heart raise (Pass, 2♥, 3♥, or 4♥).',
       validation_status = 'validated',
       is_draft = false,
       extra_hands_json = '[
         {"drill_id": "1E_H8", "lesson_code": "1E", "hand_number": 8, "label": "Lesson 1E — Validated Hand 8 (Row 2, Col 4)", "spades": "A * *", "hearts": "J * * *", "diamonds": "K Q *", "clubs": "* * *", "card_count": 13, "heart_count": 4, "spade_count": 3, "source_note": "13-card validated hand from Lesson 1E.docx (Row 2, Col 4)."},
         {"drill_id": "1E_H10", "lesson_code": "1E", "hand_number": 10, "label": "Lesson 1E — Validated Hand 10 (Row 3, Col 2)", "spades": "A *", "hearts": "Q * *", "diamonds": "* * *", "clubs": "A K * * *", "card_count": 13, "heart_count": 3, "spade_count": 2, "source_note": "13-card validated hand from Lesson 1E.docx (Row 3, Col 2)."},
         {"drill_id": "1E_H11", "lesson_code": "1E", "hand_number": 11, "label": "Lesson 1E — Validated Hand 11 (Row 3, Col 3)", "spades": "* * *", "hearts": "* * *", "diamonds": "A * *", "clubs": "J * * *", "card_count": 13, "heart_count": 3, "spade_count": 3, "source_note": "13-card validated hand from Lesson 1E.docx (Row 3, Col 3)."}
       ]'::jsonb,
       withheld_hands_json = '[
         {"hand_number": 7, "grid": "Row 2, Col 3", "holdings": "♠ A * * * | ♥ Q * * | ♦ A * * | ♣ K * * *", "reason": "Source cell (Row 2, Col 3) has 14 cards (4-3-3-4). Withheld from publication."},
         {"hand_number": 9, "grid": "Row 3, Col 1", "holdings": "♠ Q * * | ♥ K * * * | ♦ Q * * | ♣ J * * *", "reason": "Source cell (Row 3, Col 1) has 14 cards (3-4-3-4). Withheld from publication."},
         {"hand_number": 12, "grid": "Row 3, Col 4", "holdings": "♠ K | ♥ A * * * | ♦ K * * * | ♣ * * *", "reason": "Source cell (Row 3, Col 4) has 12 cards (1-4-4-3) and singleton ♠K arithmetic (13 TCP = 4♥) conflicts with 3H answer key."}
       ]'::jsonb
 WHERE code = '1E';

UPDATE public.lesson_private_materials
   SET answer_key_json = '[
         {"hand_number": 1, "hcp": 8, "dist_pts": 1, "tcp": 9, "recommended_bid": "2♥", "has_fit": true, "heart_len": 4, "spade_len": 4, "short_desc": "doubleton in ♦ (+1)", "notes": "♠A(4) + ♥A(4) = 8 HCP. 4-card ♥ support (fit). Doubleton ♦ (* *) = +1 TCP -> 9 TCP total -> 2♥ (6–9 TCP)."},
         {"hand_number": 2, "hcp": 11, "dist_pts": 1, "tcp": 12, "recommended_bid": "3♥", "has_fit": true, "heart_len": 3, "spade_len": 4, "short_desc": "doubleton in ♦ (+1)", "notes": "♠K(3) + ♥KQ(5) + ♦K(3) = 11 HCP. 3-card ♥ support (fit). Doubleton ♦ (K *) = +1 TCP -> 12 TCP total -> 3♥ (10–12 TCP)."},
         {"hand_number": 3, "hcp": 3, "dist_pts": 1, "tcp": 4, "recommended_bid": "Pass", "has_fit": true, "heart_len": 4, "spade_len": 3, "short_desc": "doubleton in ♣ (+1)", "notes": "♥K(3) = 3 HCP. 4-card ♥ support (fit). Doubleton ♣ (* *) = +1 TCP -> 4 TCP total (< 6 points) -> Pass."},
         {"hand_number": 4, "hcp": 14, "dist_pts": 1, "tcp": 15, "recommended_bid": "4♥", "has_fit": true, "heart_len": 5, "spade_len": 3, "short_desc": "doubleton in ♣ (+1)", "notes": "♠A(4) + ♥KQ(5) + ♣KQ(5) = 14 HCP. 5-card ♥ support (fit). Doubleton ♣ (K Q) = +1 TCP -> 15 TCP total -> 4♥ (13–17 TCP)."},
         {"hand_number": 5, "hcp": 4, "dist_pts": 0, "tcp": 4, "recommended_bid": "Pass", "has_fit": true, "heart_len": 3, "spade_len": 3, "short_desc": "no short suits (3-3-4-3 flat)", "notes": "♥K(3) + ♦J(1) = 4 HCP. 3-3-4-3 flat shape = 0 distribution points -> 4 TCP total (< 6 points) -> Pass."},
         {"hand_number": 6, "hcp": 9, "dist_pts": 0, "tcp": 9, "recommended_bid": "2♥", "has_fit": true, "heart_len": 3, "spade_len": 3, "short_desc": "no short suits (3-3-3-4 flat)", "notes": "♠A(4) + ♥K(3) + ♣Q(2) = 9 HCP. 3-3-3-4 flat shape = 0 distribution points -> 9 TCP total -> 2♥ (6–9 TCP)."}
       ]'::jsonb,
       extra_answer_key_json = '[
         {"hand_number": 8, "hcp": 10, "dist_pts": 0, "tcp": 10, "recommended_bid": "3♥", "has_fit": true, "heart_len": 4, "spade_len": 3, "short_desc": "no short suits (3-4-3-3 flat)", "notes": "♠A(4) + ♥J(1) + ♦KQ(5) = 10 HCP. 4-card ♥ support, flat 3-4-3-3 shape (0 dist) = 10 TCP -> 3♥ (10–12 TCP)."},
         {"hand_number": 10, "hcp": 13, "dist_pts": 1, "tcp": 14, "recommended_bid": "4♥", "has_fit": true, "heart_len": 3, "spade_len": 2, "short_desc": "doubleton in ♠ (+1)", "notes": "♠A(4) + ♥Q(2) + ♣AK(7) = 13 HCP + 1 dist (doubleton ♠ A *) = 14 TCP -> 4♥ (13–17 TCP)."},
         {"hand_number": 11, "hcp": 5, "dist_pts": 0, "tcp": 5, "recommended_bid": "Pass", "has_fit": true, "heart_len": 3, "spade_len": 3, "short_desc": "no short suits (3-3-3-4 flat)", "notes": "♦A(4) + ♣J(1) = 5 HCP. Flat 3-3-3-4 shape (0 dist) = 5 TCP (< 6 points) -> Pass."}
       ]'::jsonb
 WHERE lesson_code = '1E';

UPDATE public.lessons
   SET title = 'Lesson 1F: Responding to 1♥ Without a Heart Fit (1♠ & No-Trump)',
       subtitle = 'Validated 10-Hand Edition (Hands 1–7 & 9–11; Hands 8 & 12 Withheld)',
       objective = 'Respond to partner''s 1♥ opening when holding fewer than 3 hearts (< 3♥): bid a 4+ card spade suit first (1♠), or choose 1NT (6–9 HCP), 2NT (10–12 HCP), or 3NT (13–15 HCP, all suits stopped).',
       instructions = 'Partner opens 1♥ (5+ hearts). Because you hold only 2 hearts (< 3♥), you do NOT have a heart fit—enter 0 for Distribution Points, count your High Card Points (HCP), and choose 1♠ (if holding 4+ spades and 6+ HCP) or the appropriate No-Trump response.',
       validation_status = 'validated',
       is_draft = false,
       hands_json = '[
         {"hand_number": 1, "label": "Hand 1 (Row 1, Column 1)", "spades": "K * *", "hearts": "A *", "diamonds": "Q * * *", "clubs": "* * * *", "card_count": 13, "heart_count": 2, "spade_count": 3, "source_note": "13 cards verified from Lesson 1F.docx (Row 1, Col 1)."},
         {"hand_number": 2, "label": "Hand 2 (Row 1, Column 2)", "spades": "A * * * *", "hearts": "K Q", "diamonds": "A Q", "clubs": "* * * *", "card_count": 13, "heart_count": 2, "spade_count": 5, "source_note": "13 cards verified from Lesson 1F.docx (Row 1, Col 2)."},
         {"hand_number": 3, "label": "Hand 3 (Row 1, Column 3)", "spades": "A Q * *", "hearts": "A *", "diamonds": "* * * *", "clubs": "A * *", "card_count": 13, "heart_count": 2, "spade_count": 4, "source_note": "13 cards verified from Lesson 1F.docx (Row 1, Col 3)."},
         {"hand_number": 4, "label": "Hand 4 (Row 1, Column 4)", "spades": "A * *", "hearts": "K *", "diamonds": "* * * *", "clubs": "K * * *", "card_count": 13, "heart_count": 2, "spade_count": 3, "source_note": "13 cards verified from Lesson 1F.docx (Row 1, Col 4)."},
         {"hand_number": 5, "label": "Hand 5 (Row 2, Column 1)", "spades": "Q * *", "hearts": "K *", "diamonds": "A * * *", "clubs": "A Q * *", "card_count": 13, "heart_count": 2, "spade_count": 3, "source_note": "13 cards verified from Lesson 1F.docx (Row 2, Col 1)."},
         {"hand_number": 6, "label": "Hand 6 (Row 2, Column 2)", "spades": "* * *", "hearts": "K *", "diamonds": "A * * *", "clubs": "J * * *", "card_count": 13, "heart_count": 2, "spade_count": 3, "source_note": "13 cards verified from Lesson 1F.docx (Row 2, Col 2)."},
         {"hand_number": 7, "label": "Hand 7 (Row 2, Column 3)", "spades": "A * * *", "hearts": "Q *", "diamonds": "* * *", "clubs": "K * * *", "card_count": 13, "heart_count": 2, "spade_count": 4, "source_note": "13 cards verified from Lesson 1F.docx (Row 2, Col 3)."},
         {"hand_number": 9, "label": "Hand 9 (Row 3, Column 1)", "spades": "Q * * *", "hearts": "K *", "diamonds": "A Q * *", "clubs": "* * *", "card_count": 13, "heart_count": 2, "spade_count": 4, "source_note": "13 cards verified from Lesson 1F.docx (Row 3, Col 1)."},
         {"hand_number": 10, "label": "Hand 10 (Row 3, Column 2)", "spades": "Q * *", "hearts": "Q *", "diamonds": "* * * *", "clubs": "A K * *", "card_count": 13, "heart_count": 2, "spade_count": 3, "source_note": "13 cards verified from Lesson 1F.docx (Row 3, Col 2)."},
         {"hand_number": 11, "label": "Hand 11 (Row 3, Column 3)", "spades": "K * *", "hearts": "A *", "diamonds": "A * * *", "clubs": "Q * * *", "card_count": 13, "heart_count": 2, "spade_count": 3, "source_note": "13 cards verified from Lesson 1F.docx (Row 3, Col 3)."}
       ]'::jsonb,
       withheld_hands_json = '[
         {"hand_number": 8, "grid": "Row 2, Col 4", "holdings": "♠ A * * | ♥ K * | ♦ K Q * * | ♣ * * * *", "reason": "Source cell (Row 2, Col 4) has 12 HCP (♠A, ♥K, ♦KQ) and unstopped clubs (♣ * * * *), which matches 2NT (10–12 HCP), but Answer Key lists 3NT. Withheld pending Dennis''s confirmation."},
         {"hand_number": 12, "grid": "Row 3, Col 4", "holdings": "♠ A * * | ♥ J * | ♦ K * * | ♣ * * *", "reason": "Source cell (Row 3, Col 4) contains only 11 cards (3-2-3-3). Withheld from publication."}
       ]'::jsonb,
       transcription_flags = 'Validated 10-hand edition of Lesson 1F.docx: Hands 1–7 and 9–11 have 13 cards and 100% agreement with Answers Lesson 1E, 1F and 1G.docx. Hand 8 (12 HCP vs 3NT key) and Hand 12 (11 cards) are withheld.'
 WHERE code = '1F';

UPDATE public.lesson_private_materials
   SET answer_key_json = '[
     {"hand_number": 1, "hcp": 9, "dist_pts": 0, "tcp": 9, "recommended_bid": "1NT", "has_fit": false, "heart_len": 2, "spade_len": 3, "notes": "♠K(3) + ♥A(4) + ♦Q(2) = 9 HCP. Only 2 hearts (no fit -> 0 dist pts) and 3 spades (<4♠) -> 1NT (6–9 HCP)."},
     {"hand_number": 2, "hcp": 15, "dist_pts": 0, "tcp": 15, "recommended_bid": "1♠", "has_fit": false, "heart_len": 2, "spade_len": 5, "notes": "♠A(4) + ♥KQ(5) + ♦AQ(6) = 15 HCP. No heart fit (2♥), 5-card spade suit (4+♠) -> Bid 1♠ before No-Trump."},
     {"hand_number": 3, "hcp": 14, "dist_pts": 0, "tcp": 14, "recommended_bid": "1♠", "has_fit": false, "heart_len": 2, "spade_len": 4, "notes": "♠AQ(6) + ♥A(4) + ♣A(4) = 14 HCP. No heart fit (2♥), 4-card spade suit (4+♠) -> Bid 1♠ before No-Trump."},
     {"hand_number": 4, "hcp": 10, "dist_pts": 0, "tcp": 10, "recommended_bid": "2NT", "has_fit": false, "heart_len": 2, "spade_len": 3, "notes": "♠A(4) + ♥K(3) + ♣K(3) = 10 HCP. No heart fit (2♥) and <4♠ -> 2NT (10–12 HCP)."},
     {"hand_number": 5, "hcp": 15, "dist_pts": 0, "tcp": 15, "recommended_bid": "3NT", "has_fit": false, "heart_len": 2, "spade_len": 3, "notes": "♠Q(2) + ♥K(3) + ♦A(4) + ♣AQ(6) = 15 HCP. No heart fit (2♥), all suits stopped, 13–15 HCP -> 3NT."},
     {"hand_number": 6, "hcp": 8, "dist_pts": 0, "tcp": 8, "recommended_bid": "1NT", "has_fit": false, "heart_len": 2, "spade_len": 3, "notes": "♥K(3) + ♦A(4) + ♣J(1) = 8 HCP. No heart fit (2♥) and <4♠ -> 1NT (6–9 HCP)."},
     {"hand_number": 7, "hcp": 9, "dist_pts": 0, "tcp": 9, "recommended_bid": "1♠", "has_fit": false, "heart_len": 2, "spade_len": 4, "notes": "♠A(4) + ♥Q(2) + ♣K(3) = 9 HCP. 4-card spade suit (4+♠) takes priority over 1NT -> 1♠."},
     {"hand_number": 9, "hcp": 11, "dist_pts": 0, "tcp": 11, "recommended_bid": "1♠", "has_fit": false, "heart_len": 2, "spade_len": 4, "notes": "♠Q(2) + ♥K(3) + ♦AQ(6) = 11 HCP. 4-card spade suit (4+♠) takes priority over 2NT -> 1♠."},
     {"hand_number": 10, "hcp": 11, "dist_pts": 0, "tcp": 11, "recommended_bid": "2NT", "has_fit": false, "heart_len": 2, "spade_len": 3, "notes": "♠Q(2) + ♥Q(2) + ♣AK(7) = 11 HCP. No heart fit (2♥) and <4♠ -> 2NT (10–12 HCP)."},
     {"hand_number": 11, "hcp": 13, "dist_pts": 0, "tcp": 13, "recommended_bid": "3NT", "has_fit": false, "heart_len": 2, "spade_len": 3, "notes": "♠K(3) + ♥A(4) + ♦A(4) + ♣Q(2) = 13 HCP. No heart fit (2♥), all suits covered, 13–15 HCP -> 3NT."}
   ]'::jsonb,
       organiser_source_notes = 'Validated 10 hands from Lesson 1F.docx against Answers Lesson 1E, 1F and 1G.docx. Hand 8 (12 HCP with ♣**** vs 3NT key) and Hand 12 (11 cards) are withheld in withheld_hands_json.'
 WHERE lesson_code = '1F';

UPDATE public.lessons
   SET title = 'Lesson 1G: New Minor at 2-Level, Weak Jumps & 4♣ Ace-Ask (Awaiting Source Audit)',
       subtitle = 'Locked Pending Resolution of 7 Source Anomalies in Lesson 1G.docx',
       objective = 'Respond with 5+ card minor suits at the 2-level (2♣/2♦), 7-card minor weak jumps (3♣/3♦), or 4♣ Ace-ask.',
       validation_status = 'awaiting_source_resolution',
       is_draft = true,
       withheld_hands_json = '[
         {"hand_number": 1, "grid": "Row 1, Col 1", "holdings": "♠ A Q * * * * | ♥ Q * | ♦ * * | ♣ * * *", "reason": "6 spades & 8 HCP: sheet header says 2♠ weak jump (6–9 HCP, 6♠), but Answer Key bids 1S."},
         {"hand_number": 2, "grid": "Row 1, Col 2", "holdings": "♠ A * * * | ♥ K Q * * | ♦ A Q | ♣ Q *", "reason": "Source cell (Row 1, Col 2) contains only 12 cards (4-4-2-2)."},
         {"hand_number": 4, "grid": "Row 1, Col 4", "holdings": "♠ * * * | ♥ K * | ♦ * | ♣ K Q * * * * * *", "reason": "Source cell (Row 1, Col 4) contains 14 cards (3-2-1-8)."},
         {"hand_number": 7, "grid": "Row 2, Col 3", "holdings": "♠ A * * * * * | ♥ Q * | ♦ * * * | ♣ * *", "reason": "6 spades & 6 HCP: sheet header says 2♠ weak jump, but Answer Key bids 1S."},
         {"hand_number": 8, "grid": "Row 2, Col 4", "holdings": "♠ A K * | ♥ J * | ♦ K Q * * * | ♣ A Q *", "reason": "19 HCP & <3♥: sheet header says 4♣ = <3H and 18+ HCP, but Answer Key footnote says go up gradually (2D) without a heart fit."},
         {"hand_number": 11, "grid": "Row 3, Col 3", "holdings": "♠ K Q * * | ♥ A * * | ♦ A * * | ♣ A Q *", "reason": "19 HCP & 3 hearts (♥ A * * = heart fit!): meets 4♣ (3+♥ and 18+ TCP) rule, but Answer Key bids 1S."},
         {"hand_number": 12, "grid": "Row 3, Col 4", "holdings": "♠ Q J * * * * | ♥ J * * | ♦ K * | ♣ * *", "reason": "7 HCP, 3 hearts (♥ J * * = 9 TCP heart fit = 2♥) and 6 spades (2♠), but Answer Key bids 1S."}
       ]'::jsonb
 WHERE code = '1G';

-- =============================================================================
-- 6. REPLACED LEARNER PORTAL RPC (`public.learner_get_portal`)
--    Returns member, club_settings, all_lessons_catalog, assignments (with
--    submissions.grading_json & feedback), mistake_queue, notifications,
--    directory (no email or organiser notes), friendships, community_posts
--    (filtered by moderation & blocks, with comments), and practice_sessions.
-- =============================================================================
CREATE OR REPLACE FUNCTION public.learner_get_portal(p_raw_token text)
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
    v_expires_at timestamptz;
    v_hash text;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);
    v_hash := encode(extensions.digest(convert_to(lower(trim(p_raw_token)), 'UTF8'), 'sha256'), 'hex');

    SELECT li.expires_at INTO v_expires_at
      FROM public.learner_invitations li
     WHERE li.token_hash = v_hash;

    SELECT jsonb_build_object(
        'id', m.id,
        'name', m.name,
        'experience', m.experience,
        'availability_pkt', m.availability_pkt,
        'invitation_expires_at', v_expires_at
    )
    INTO v_member
    FROM public.members m
    WHERE m.id = v_member_id;

    SELECT jsonb_build_object(
        'progression_threshold_pct', coalesce(cs.progression_threshold_pct, 80),
        'answer_key_version', coalesce(cs.answer_key_version, 'v2.0-2026-10-27')
    )
    INTO v_club_settings
    FROM public.club_settings cs
    WHERE cs.id = 1;

    v_club_settings := coalesce(v_club_settings, '{"progression_threshold_pct": 80, "answer_key_version": "v2.0-2026-10-27"}'::jsonb);

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

    -- Fetch ONLY explicitly unlocked/assigned lessons for this learner, including submissions.grading_json
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

    -- Personal "Practice Again" mistake queue
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

    -- Visible community posts (excluding hidden_by_mod and mutually blocked authors)
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
            'external_bbo_note', ps.external_bbo_note,
            'max_players', ps.max_players,
            'created_at', ps.created_at,
            'player_names', coalesce((
                SELECT jsonb_agg( coalesce(rm.name, 'Member') ORDER BY r.created_at ASC )
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
        'community_posts', v_posts,
        'practice_sessions', v_sessions
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_get_portal(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_get_portal(text) TO anon, authenticated;

-- =============================================================================
-- 7. DETERMINISTIC BACKEND GRADING & AUTOMATIC PROGRESSION RPC
-- =============================================================================
CREATE OR REPLACE FUNCTION public.learner_submit_and_grade_lesson(
    p_raw_token text,
    p_lesson_code text,
    p_answers_json jsonb,
    p_learner_questions text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_assignment RECORD;
    v_lesson RECORD;
    v_key_array jsonb;
    v_threshold integer;
    v_key_ver text;
    v_item jsonb;
    v_hand_num text;
    v_ans jsonb;
    v_exp_hcp integer;
    v_exp_dist integer;
    v_exp_tcp integer;
    v_exp_bid text;
    v_user_hcp integer;
    v_user_dist integer;
    v_user_bid text;
    v_hcp_ok boolean;
    v_dist_ok boolean;
    v_bid_ok boolean;
    v_total_components integer := 0;
    v_earned_components integer := 0;
    v_hcp_correct integer := 0;
    v_dist_correct integer := 0;
    v_bid_correct integer := 0;
    v_hand_count integer := 0;
    v_breakdown jsonb := '[]'::jsonb;
    v_diag text;
    v_missed jsonb;
    v_score_pct integer;
    v_passed boolean;
    v_sub_id uuid;
    v_ver integer;
    v_latest_sub RECORD;
    v_next_code text;
    v_next_lesson RECORD;
    v_unlocked_next text := NULL;
    v_next_status_note text := '';
    v_grading_payload jsonb;
    v_clean_q text;
    v_has_q boolean;
    v_final_sub_status text;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);
    v_clean_q := public.sanitize_club_text(p_learner_questions);
    v_has_q := char_length(v_clean_q) > 0;

    SELECT la.id, la.status
      INTO v_assignment
      FROM public.lesson_assignments la
     WHERE la.member_id = v_member_id
       AND la.lesson_code = p_lesson_code
     LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_ASSIGNED: Lesson % has not been unlocked for your account.', p_lesson_code
            USING ERRCODE = '42501';
    END IF;

    IF v_assignment.status = 'Paused' THEN
        RAISE EXCEPTION 'ASSIGNMENT_PAUSED: This lesson assignment is currently paused.'
            USING ERRCODE = '42501';
    END IF;

    -- Idempotency check against rapid double-click (< 3 seconds with identical payload)
    SELECT s.id, s.version_number, s.status, s.answers_json, s.learner_questions, s.grading_json, s.submitted_at
      INTO v_latest_sub
      FROM public.submissions s
     WHERE s.assignment_id = v_assignment.id
       AND s.member_id = v_member_id
       AND s.status <> 'draft'
     ORDER BY s.version_number DESC
     LIMIT 1;

    IF FOUND
       AND v_latest_sub.answers_json = coalesce(p_answers_json, '{}'::jsonb)
       AND v_latest_sub.learner_questions = v_clean_q
       AND v_latest_sub.submitted_at >= (now() - interval '3 seconds') THEN
        RETURN jsonb_build_object(
            'submission_id', v_latest_sub.id,
            'version_number', v_latest_sub.version_number,
            'status', v_latest_sub.status,
            'grading', v_latest_sub.grading_json,
            'deduplicated', true
        );
    END IF;

    SELECT l.code, l.is_draft, l.validation_status, l.hands_json
      INTO v_lesson
      FROM public.lessons l
     WHERE l.code = p_lesson_code;

    IF v_lesson.is_draft OR v_lesson.validation_status <> 'validated' THEN
        RAISE EXCEPTION 'LESSON_NOT_VALIDATED: Lesson % is not published for automated grading.', p_lesson_code
            USING ERRCODE = '22023';
    END IF;

    SELECT lpm.answer_key_json INTO v_key_array
      FROM public.lesson_private_materials lpm
     WHERE lpm.lesson_code = p_lesson_code;

    SELECT cs.progression_threshold_pct, cs.answer_key_version
      INTO v_threshold, v_key_ver
      FROM public.club_settings cs
     WHERE cs.id = 1;

    v_threshold := coalesce(v_threshold, 80);
    v_key_ver := coalesce(v_key_ver, 'v2.0-2026-10-27');

    -- Deterministically grade each validated hand (3 components per hand: HCP, Dist, Bid)
    FOR v_item IN SELECT * FROM jsonb_array_elements(v_key_array)
    LOOP
        v_hand_count := v_hand_count + 1;
        v_hand_num := (v_item->>'hand_number');
        v_exp_hcp := (v_item->>'hcp')::integer;
        v_exp_dist := (v_item->>'dist_pts')::integer;
        v_exp_tcp := (v_item->>'tcp')::integer;
        v_exp_bid := (v_item->>'recommended_bid');

        v_ans := coalesce(p_answers_json->v_hand_num, '{}'::jsonb);
        BEGIN
            v_user_hcp := nullif(regexp_replace(coalesce(v_ans->>'hcp', v_ans->>'tcp', ''), '[^0-9-]', '', 'g'), '')::integer;
        EXCEPTION WHEN OTHERS THEN
            v_user_hcp := NULL;
        END;
        BEGIN
            v_user_dist := nullif(regexp_replace(coalesce(v_ans->>'dist_pts', '0'), '[^0-9-]', '', 'g'), '')::integer;
        EXCEPTION WHEN OTHERS THEN
            v_user_dist := NULL;
        END;
        v_user_bid := trim(coalesce(v_ans->>'bid', ''));
        IF upper(v_user_bid) IN ('P', 'PASS') THEN v_user_bid := 'Pass'; END IF;
        v_user_bid := replace(replace(replace(replace(upper(v_user_bid), 'PASS', 'Pass'), 'S', '♠'), 'H', '♥'), 'D', '♦');
        v_user_bid := replace(v_user_bid, 'C', '♣');

        v_hcp_ok := (v_user_hcp IS NOT NULL AND v_user_hcp = v_exp_hcp);
        v_dist_ok := (v_user_dist IS NOT NULL AND v_user_dist = v_exp_dist);
        v_bid_ok := (v_user_bid = v_exp_bid);

        v_total_components := v_total_components + 3;
        IF v_hcp_ok THEN v_earned_components := v_earned_components + 1; v_hcp_correct := v_hcp_correct + 1; END IF;
        IF v_dist_ok THEN v_earned_components := v_earned_components + 1; v_dist_correct := v_dist_correct + 1; END IF;
        IF v_bid_ok THEN v_earned_components := v_earned_components + 1; v_bid_correct := v_bid_correct + 1; END IF;

        v_diag := '';
        v_missed := '[]'::jsonb;

        IF NOT v_hcp_ok THEN
            v_missed := v_missed || '["honour_counting"]'::jsonb;
            IF abs(coalesce(v_user_hcp, -99) - v_exp_hcp) = 1 THEN
                v_diag := v_diag || format('Jack counted incorrectly: your HCP (%s) is off by 1 point from %s HCP (remember Ace=4, King=3, Queen=2, Jack=1). ', coalesce(v_user_hcp::text, 'blank'), v_exp_hcp);
            ELSE
                v_diag := v_diag || format('Honour count: expected %s HCP (A=4, K=3, Q=2, J=1), you entered %s. ', v_exp_hcp, coalesce(v_user_hcp::text, 'blank'));
            END IF;
        END IF;

        IF NOT v_dist_ok THEN
            v_missed := v_missed || '["distribution", "fit_recognition"]'::jsonb;
            IF v_hcp_ok AND v_exp_dist = 1 AND coalesce(v_user_dist, 0) = 0 THEN
                v_diag := v_diag || format('Honour points (%s HCP) are correct, but a +%s doubleton distribution point was omitted with 3+ card heart support. ', v_exp_hcp, v_exp_dist);
            ELSIF v_exp_dist = 0 AND coalesce(v_user_dist, 0) > 0 THEN
                v_diag := v_diag || 'Distribution points should be 0 here (either flat 4-3-3-3 shape or fewer than 3 hearts so no heart fit). ';
            ELSE
                v_diag := v_diag || format('Expected %s distribution points, you entered %s. ', v_exp_dist, coalesce(v_user_dist::text, 'blank'));
            END IF;
        END IF;

        IF NOT v_bid_ok THEN
            v_missed := v_missed || '["response_selection"]'::jsonb;
            v_diag := v_diag || format('Expected bid %s (%s), you chose %s.', v_exp_bid, coalesce(v_item->>'notes', ''), coalesce(nullif(v_user_bid, ''), 'blank'));
        END IF;

        IF v_hcp_ok AND v_dist_ok AND v_bid_ok THEN
            v_diag := format('Spot on! %s HCP + %s Dist = %s TCP -> %s. %s', v_exp_hcp, v_exp_dist, v_exp_tcp, v_exp_bid, coalesce(v_item->>'notes', ''));
            UPDATE public.learner_mistake_queue
               SET mastered = true, last_diagnostic = v_diag, updated_at = now()
             WHERE member_id = v_member_id AND lesson_code = p_lesson_code AND hand_number = v_hand_num::integer;
        ELSE
            INSERT INTO public.learner_mistake_queue (
                member_id, lesson_code, hand_number, missed_skills, last_diagnostic, times_missed, mastered, updated_at
            ) VALUES (
                v_member_id, p_lesson_code, v_hand_num::integer, v_missed, trim(v_diag), 1, false, now()
            )
            ON CONFLICT (member_id, lesson_code, hand_number) DO UPDATE
               SET missed_skills = EXCLUDED.missed_skills,
                   last_diagnostic = EXCLUDED.last_diagnostic,
                   times_missed = public.learner_mistake_queue.times_missed + 1,
                   mastered = false,
                   updated_at = now();
        END IF;

        v_breakdown := v_breakdown || jsonb_build_array(jsonb_build_object(
            'hand_number', v_hand_num::integer,
            'user_hcp', v_user_hcp,
            'expected_hcp', v_exp_hcp,
            'hcp_ok', v_hcp_ok,
            'user_dist', v_user_dist,
            'expected_dist', v_exp_dist,
            'dist_ok', v_dist_ok,
            'calculated_tcp', coalesce(v_user_hcp, 0) + coalesce(v_user_dist, 0),
            'expected_tcp', v_exp_tcp,
            'user_bid', v_user_bid,
            'expected_bid', v_exp_bid,
            'bid_ok', v_bid_ok,
            'missed_skills', v_missed,
            'explanation', trim(v_diag)
        ));
    END LOOP;

    v_score_pct := CASE WHEN v_total_components > 0 THEN round((v_earned_components::numeric / v_total_components::numeric) * 100)::integer ELSE 0 END;
    v_passed := (v_score_pct >= v_threshold);

    -- Check automatic unlock of the next published, validated lesson (1E -> 1F -> 1G)
    IF v_passed THEN
        v_next_code := CASE p_lesson_code WHEN '1E' THEN '1F' WHEN '1F' THEN '1G' ELSE NULL END;
        IF v_next_code IS NOT NULL THEN
            SELECT l.code, l.is_draft, l.validation_status, l.hands_json
              INTO v_next_lesson
              FROM public.lessons l
             WHERE l.code = v_next_code;

            IF FOUND AND NOT v_next_lesson.is_draft AND v_next_lesson.validation_status = 'validated' AND jsonb_array_length(v_next_lesson.hands_json) > 0 THEN
                IF NOT EXISTS (
                    SELECT 1 FROM public.lesson_assignments la2
                     WHERE la2.member_id = v_member_id AND la2.lesson_code = v_next_code
                ) THEN
                    INSERT INTO public.lesson_assignments (member_id, lesson_code, status, released_at)
                    VALUES (v_member_id, v_next_code, 'Not started', now());
                    v_unlocked_next := v_next_code;
                    INSERT INTO public.member_notifications (member_id, kind, title, body)
                    VALUES (
                        v_member_id,
                        'unlock',
                        format('Lesson %s Unlocked Automatically!', v_next_code),
                        format('You scored %s%% (%s/%s) on Lesson %s, meeting the %s%% threshold.', v_score_pct, v_earned_components, v_total_components, p_lesson_code, v_threshold)
                    );
                END IF;
                v_next_status_note := format('Congratulations! You scored %s%% (%s/%s components >= %s%% threshold). Lesson %s is unlocked and ready!', v_score_pct, v_earned_components, v_total_components, v_threshold, v_next_code);
            ELSE
                v_next_status_note := format('You mastered Lesson %s (%s%% >= %s%%)! Next lesson %s is currently locked awaiting source validation of flagged exercises.', p_lesson_code, v_score_pct, v_threshold, v_next_code);
            END IF;
        END IF;
    ELSE
        v_next_status_note := format('You scored %s%% (%s/%s components). Review the diagnostic explanations below, practise missed hands in "Practice Again", and retry to reach %s%% and unlock the next lesson.', v_score_pct, v_earned_components, v_total_components, v_threshold);
    END IF;

    v_grading_payload := jsonb_build_object(
        'answer_key_version', v_key_ver,
        'graded_at', now(),
        'earned_components', v_earned_components,
        'total_components', v_total_components,
        'denominator_explanation', format('%s hands × 3 scored skills (HCP, Distribution Points, Bid) = %s components. Calculated TCP and optional reasoning/questions are never counted as wrong answers.', v_hand_count, v_total_components),
        'score_pct', v_score_pct,
        'progression_threshold_pct', v_threshold,
        'passed', v_passed,
        'unlocked_next_lesson', v_unlocked_next,
        'next_action_summary', v_next_status_note,
        'skill_breakdown', jsonb_build_object(
            'honour_counting_pct', CASE WHEN v_hand_count > 0 THEN round((v_hcp_correct::numeric / v_hand_count::numeric) * 100)::integer ELSE 0 END,
            'distribution_pct', CASE WHEN v_hand_count > 0 THEN round((v_dist_correct::numeric / v_hand_count::numeric) * 100)::integer ELSE 0 END,
            'fit_recognition_pct', CASE WHEN v_hand_count > 0 THEN round((v_dist_correct::numeric / v_hand_count::numeric) * 100)::integer ELSE 0 END,
            'response_selection_pct', CASE WHEN v_hand_count > 0 THEN round((v_bid_correct::numeric / v_hand_count::numeric) * 100)::integer ELSE 0 END
        ),
        'hands_breakdown', v_breakdown
    );

    v_final_sub_status := CASE WHEN v_has_q THEN 'submitted' ELSE 'reviewed' END;

    -- Save immutable versioned submission with grading_json
    SELECT s.id, s.version_number
      INTO v_sub_id, v_ver
      FROM public.submissions s
     WHERE s.assignment_id = v_assignment.id
       AND s.member_id = v_member_id
       AND s.status = 'draft'
     ORDER BY s.version_number DESC
     LIMIT 1;

    IF v_sub_id IS NOT NULL THEN
        UPDATE public.submissions
           SET answers_json = coalesce(p_answers_json, '{}'::jsonb),
               learner_questions = v_clean_q,
               grading_json = v_grading_payload,
               status = v_final_sub_status,
               submitted_at = now(),
               reviewed_at = CASE WHEN v_has_q THEN NULL ELSE now() END,
               updated_at = now()
         WHERE id = v_sub_id;
    ELSE
        SELECT coalesce(max(s.version_number), 0) + 1
          INTO v_ver
          FROM public.submissions s
         WHERE s.assignment_id = v_assignment.id;

        INSERT INTO public.submissions (
            assignment_id, member_id, lesson_code, version_number, status,
            answers_json, learner_questions, grading_json, submitted_at, reviewed_at
        ) VALUES (
            v_assignment.id, v_member_id, p_lesson_code, v_ver, v_final_sub_status,
            coalesce(p_answers_json, '{}'::jsonb), v_clean_q,
            v_grading_payload, now(), CASE WHEN v_has_q THEN NULL ELSE now() END
        )
        RETURNING id INTO v_sub_id;
    END IF;

    UPDATE public.lesson_assignments
       SET status = CASE
               WHEN v_has_q THEN 'Needs help'
               WHEN v_passed THEN 'Finished'
               ELSE 'Working on it'
           END,
           finished_at = CASE WHEN v_passed THEN coalesce(finished_at, CURRENT_DATE) ELSE finished_at END,
           updated_at = now()
     WHERE id = v_assignment.id;

    UPDATE public.members
       SET interest_status = CASE
               WHEN interest_status IN ('Not contacted', 'Awaiting reply') THEN 'Interested'
               ELSE interest_status
           END,
           updated_at = now()
     WHERE id = v_member_id;

    RETURN jsonb_build_object(
        'submission_id', v_sub_id,
        'version_number', v_ver,
        'status', v_final_sub_status,
        'grading', v_grading_payload
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_submit_and_grade_lesson(text, text, jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_submit_and_grade_lesson(text, text, jsonb, text) TO anon, authenticated;

-- =============================================================================
-- 8. LIVE PRACTICE HAND CHECK & MASTERY PERSISTENCE (`learner_check_practice_hand`)
-- =============================================================================
CREATE OR REPLACE FUNCTION public.learner_check_practice_hand(
    p_raw_token text,
    p_lesson_code text,
    p_hand_number integer,
    p_user_ans jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_all_keys jsonb;
    v_item jsonb;
    v_exp_hcp integer;
    v_exp_dist integer;
    v_exp_tcp integer;
    v_exp_bid text;
    v_user_hcp integer;
    v_user_dist integer;
    v_user_bid text;
    v_hcp_ok boolean;
    v_dist_ok boolean;
    v_bid_ok boolean;
    v_diag text := '';
    v_missed jsonb := '[]'::jsonb;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);

    SELECT coalesce(lpm.answer_key_json, '[]'::jsonb) || coalesce(lpm.extra_answer_key_json, '[]'::jsonb)
      INTO v_all_keys
      FROM public.lesson_private_materials lpm
     WHERE lpm.lesson_code = p_lesson_code;

    IF v_all_keys IS NULL THEN
        RAISE EXCEPTION 'NOT_FOUND: Practice lesson % not found.', p_lesson_code
            USING ERRCODE = 'P0002';
    END IF;

    SELECT elem INTO v_item
      FROM jsonb_array_elements(v_all_keys) elem
     WHERE (elem->>'hand_number')::integer = p_hand_number
     LIMIT 1;

    IF v_item IS NULL THEN
        RAISE EXCEPTION 'NOT_FOUND: Hand % in Lesson % is not in the validated practice bank.', p_hand_number, p_lesson_code
            USING ERRCODE = 'P0002';
    END IF;

    v_exp_hcp := (v_item->>'hcp')::integer;
    v_exp_dist := (v_item->>'dist_pts')::integer;
    v_exp_tcp := (v_item->>'tcp')::integer;
    v_exp_bid := (v_item->>'recommended_bid');

    BEGIN
        v_user_hcp := nullif(regexp_replace(coalesce(p_user_ans->>'hcp', ''), '[^0-9-]', '', 'g'), '')::integer;
    EXCEPTION WHEN OTHERS THEN
        v_user_hcp := NULL;
    END;
    BEGIN
        v_user_dist := nullif(regexp_replace(coalesce(p_user_ans->>'dist_pts', '0'), '[^0-9-]', '', 'g'), '')::integer;
    EXCEPTION WHEN OTHERS THEN
        v_user_dist := NULL;
    END;

    v_user_bid := trim(coalesce(p_user_ans->>'bid', ''));
    IF upper(v_user_bid) IN ('P', 'PASS') THEN v_user_bid := 'Pass'; END IF;
    v_user_bid := replace(replace(replace(replace(upper(v_user_bid), 'PASS', 'Pass'), 'S', '♠'), 'H', '♥'), 'D', '♦');
    v_user_bid := replace(v_user_bid, 'C', '♣');

    v_hcp_ok := (v_user_hcp IS NOT NULL AND v_user_hcp = v_exp_hcp);
    v_dist_ok := (v_user_dist IS NOT NULL AND v_user_dist = v_exp_dist);
    v_bid_ok := (v_user_bid = v_exp_bid);

    IF NOT v_hcp_ok THEN
        v_missed := v_missed || '["honour_counting"]'::jsonb;
        v_diag := v_diag || format('Expected %s HCP (A=4, K=3, Q=2, J=1), you entered %s. ', v_exp_hcp, coalesce(v_user_hcp::text, 'blank'));
    END IF;

    IF NOT v_dist_ok THEN
        v_missed := v_missed || '["distribution", "fit_recognition"]'::jsonb;
        v_diag := v_diag || format('Expected %s distribution points, you entered %s. ', v_exp_dist, coalesce(v_user_dist::text, 'blank'));
    END IF;

    IF NOT v_bid_ok THEN
        v_missed := v_missed || '["response_selection"]'::jsonb;
        v_diag := v_diag || format('Expected bid %s (%s), you selected %s.', v_exp_bid, coalesce(v_item->>'notes', ''), coalesce(nullif(v_user_bid, ''), 'blank'));
    END IF;

    IF v_hcp_ok AND v_dist_ok AND v_bid_ok THEN
        v_diag := format('Spot on! %s HCP + %s Dist = %s TCP -> %s. %s', v_exp_hcp, v_exp_dist, v_exp_tcp, v_exp_bid, coalesce(v_item->>'notes', ''));
        UPDATE public.learner_mistake_queue
           SET mastered = true,
               last_diagnostic = v_diag,
               updated_at = now()
         WHERE member_id = v_member_id
           AND lesson_code = p_lesson_code
           AND hand_number = p_hand_number;
    ELSE
        UPDATE public.learner_mistake_queue
           SET mastered = false,
               missed_skills = v_missed,
               last_diagnostic = trim(v_diag),
               times_missed = times_missed + 1,
               updated_at = now()
         WHERE member_id = v_member_id
           AND lesson_code = p_lesson_code
           AND hand_number = p_hand_number;
    END IF;

    RETURN jsonb_build_object(
        'hand_number', p_hand_number,
        'user_hcp', v_user_hcp,
        'expected_hcp', v_exp_hcp,
        'hcp_ok', v_hcp_ok,
        'user_dist', v_user_dist,
        'expected_dist', v_exp_dist,
        'dist_ok', v_dist_ok,
        'calculated_tcp', coalesce(v_user_hcp, 0) + coalesce(v_user_dist, 0),
        'expected_tcp', v_exp_tcp,
        'user_bid', v_user_bid,
        'expected_bid', v_exp_bid,
        'bid_ok', v_bid_ok,
        'missed_skills', v_missed,
        'explanation', trim(v_diag)
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_check_practice_hand(text, text, integer, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_check_practice_hand(text, text, integer, jsonb) TO anon, authenticated;

-- =============================================================================
-- 9. LEARNER PROFILE, FRIENDSHIPS/BLOCKS, POSTS, COMMENTS, REPORTS & SESSIONS
-- =============================================================================

CREATE OR REPLACE FUNCTION public.learner_update_profile(
    p_raw_token text,
    p_display_name text,
    p_experience text,
    p_availability_pkt text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_clean_name text;
    v_clean_avail text;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);
    v_clean_name := public.sanitize_club_text(p_display_name);
    v_clean_avail := public.sanitize_club_text(p_availability_pkt);

    IF char_length(v_clean_name) = 0 OR char_length(v_clean_name) > 100 THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Display name must be between 1 and 100 characters.'
            USING ERRCODE = '22023';
    END IF;

    IF p_experience NOT IN ('New to bridge', 'Learning', 'Comfortable playing', 'Can help teach') THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Invalid experience level.'
            USING ERRCODE = '22023';
    END IF;

    UPDATE public.members
       SET name = v_clean_name,
           experience = p_experience,
           availability_pkt = v_clean_avail,
           updated_at = now()
     WHERE id = v_member_id;

    RETURN jsonb_build_object(
        'status', 'ok',
        'member_id', v_member_id,
        'name', v_clean_name,
        'experience', p_experience,
        'availability_pkt', v_clean_avail
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_update_profile(text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_update_profile(text, text, text, text) TO anon, authenticated;

CREATE OR REPLACE FUNCTION public.learner_manage_friendship(
    p_raw_token text,
    p_target_member_id uuid,
    p_action text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_my_name text;
    v_existing RECORD;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);

    IF v_member_id = p_target_member_id THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Cannot target your own profile.'
            USING ERRCODE = '22023';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.members WHERE id = p_target_member_id AND interest_status <> 'Not interested') THEN
        RAISE EXCEPTION 'NOT_FOUND: Target club member not found.'
            USING ERRCODE = 'P0002';
    END IF;

    IF p_action NOT IN ('request', 'accept', 'decline', 'remove', 'block', 'unblock') THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Invalid friendship action %.', p_action
            USING ERRCODE = '22023';
    END IF;

    SELECT m.name INTO v_my_name FROM public.members m WHERE m.id = v_member_id;

    IF p_action = 'block' THEN
        INSERT INTO public.member_blocks (blocker_id, blocked_id)
        VALUES (v_member_id, p_target_member_id)
        ON CONFLICT (blocker_id, blocked_id) DO NOTHING;

        DELETE FROM public.member_friendships
         WHERE (requester_id = v_member_id AND addressee_id = p_target_member_id)
            OR (requester_id = p_target_member_id AND addressee_id = v_member_id);

    ELSIF p_action = 'unblock' THEN
        DELETE FROM public.member_blocks
         WHERE blocker_id = v_member_id AND blocked_id = p_target_member_id;

    ELSIF p_action = 'request' THEN
        IF EXISTS (
            SELECT 1 FROM public.member_blocks mb
             WHERE (mb.blocker_id = v_member_id AND mb.blocked_id = p_target_member_id)
                OR (mb.blocker_id = p_target_member_id AND mb.blocked_id = v_member_id)
        ) THEN
            RAISE EXCEPTION 'BLOCKED: Cannot send friend request to a blocked profile.'
                USING ERRCODE = '42501';
        END IF;

        SELECT * INTO v_existing
          FROM public.member_friendships mf
         WHERE (mf.requester_id = v_member_id AND mf.addressee_id = p_target_member_id)
            OR (mf.requester_id = p_target_member_id AND mf.addressee_id = v_member_id)
         LIMIT 1;

        IF FOUND THEN
            UPDATE public.member_friendships
               SET requester_id = v_member_id,
                   addressee_id = p_target_member_id,
                   status = 'pending',
                   updated_at = now()
             WHERE id = v_existing.id;
        ELSE
            INSERT INTO public.member_friendships (requester_id, addressee_id, status)
            VALUES (v_member_id, p_target_member_id, 'pending');
        END IF;

        INSERT INTO public.member_notifications (member_id, kind, title, body)
        VALUES (
            p_target_member_id,
            'friend_request',
            format('Friend Request from %s', v_my_name),
            format('%s invited you to connect as a bridge study partner.', v_my_name)
        );

    ELSIF p_action IN ('accept', 'decline') THEN
        UPDATE public.member_friendships
           SET status = CASE WHEN p_action = 'accept' THEN 'accepted' ELSE 'declined' END,
               updated_at = now()
         WHERE (requester_id = p_target_member_id AND addressee_id = v_member_id)
            OR (requester_id = v_member_id AND addressee_id = p_target_member_id);

        IF NOT FOUND THEN
            RAISE EXCEPTION 'NOT_FOUND: No pending friend request found.'
                USING ERRCODE = 'P0002';
        END IF;

        IF p_action = 'accept' THEN
            INSERT INTO public.member_notifications (member_id, kind, title, body)
            VALUES (
                p_target_member_id,
                'friend_accepted',
                format('%s accepted your friend request', v_my_name),
                format('You and %s are now connected as study partners.', v_my_name)
            );
        END IF;

    ELSIF p_action = 'remove' THEN
        DELETE FROM public.member_friendships
         WHERE (requester_id = v_member_id AND addressee_id = p_target_member_id)
            OR (requester_id = p_target_member_id AND addressee_id = v_member_id);
    END IF;

    RETURN jsonb_build_object('status', 'ok', 'action', p_action, 'target_member_id', p_target_member_id);
END;
$$;

REVOKE ALL ON FUNCTION public.learner_manage_friendship(text, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_manage_friendship(text, uuid, text) TO anon, authenticated;

CREATE OR REPLACE FUNCTION public.learner_create_post(
    p_raw_token text,
    p_category text,
    p_title text,
    p_body text,
    p_lesson_code text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_clean_title text;
    v_clean_body text;
    v_cat text;
    v_post RECORD;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);
    v_clean_title := public.sanitize_club_text(p_title);
    v_clean_body := public.sanitize_club_text(p_body);
    v_cat := coalesce(nullif(trim(p_category), ''), 'General');

    IF v_cat NOT IN ('General', 'Lesson Question', 'Practice Arrangement', 'Club Announcement') THEN
        v_cat := 'General';
    END IF;

    IF char_length(v_clean_title) = 0 OR char_length(v_clean_body) = 0 THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Post title and message body are required.'
            USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.community_posts (
        author_id, category, lesson_code, title, body, moderation_status
    ) VALUES (
        v_member_id,
        v_cat,
        CASE WHEN p_lesson_code IN ('1E', '1F', '1G') THEN p_lesson_code ELSE NULL END,
        v_clean_title,
        v_clean_body,
        'visible'
    )
    RETURNING * INTO v_post;

    RETURN jsonb_build_object(
        'id', v_post.id,
        'author_id', v_post.author_id,
        'category', v_post.category,
        'lesson_code', v_post.lesson_code,
        'title', v_post.title,
        'body', v_post.body,
        'moderation_status', v_post.moderation_status,
        'created_at', v_post.created_at
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_create_post(text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_create_post(text, text, text, text, text) TO anon, authenticated;

CREATE OR REPLACE FUNCTION public.learner_add_comment(
    p_raw_token text,
    p_post_id uuid,
    p_body text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_my_name text;
    v_post RECORD;
    v_clean_body text;
    v_comm RECORD;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);
    v_clean_body := public.sanitize_club_text(p_body);

    IF char_length(v_clean_body) = 0 THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Comment text cannot be empty.'
            USING ERRCODE = '22023';
    END IF;

    SELECT p.id, p.author_id, p.title, p.moderation_status
      INTO v_post
      FROM public.community_posts p
     WHERE p.id = p_post_id
     LIMIT 1;

    IF NOT FOUND OR v_post.moderation_status = 'hidden_by_mod' THEN
        RAISE EXCEPTION 'NOT_FOUND: Discussion post is not available.'
            USING ERRCODE = 'P0002';
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.member_blocks mb
         WHERE (mb.blocker_id = v_member_id AND mb.blocked_id = v_post.author_id)
            OR (mb.blocker_id = v_post.author_id AND mb.blocked_id = v_member_id)
    ) THEN
        RAISE EXCEPTION 'BLOCKED: Cannot comment on this post.'
            USING ERRCODE = '42501';
    END IF;

    SELECT m.name INTO v_my_name FROM public.members m WHERE m.id = v_member_id;

    INSERT INTO public.community_comments (
        post_id, author_id, body, is_organiser_reply, moderation_status
    ) VALUES (
        p_post_id, v_member_id, v_clean_body, false, 'visible'
    )
    RETURNING * INTO v_comm;

    IF v_post.author_id <> v_member_id THEN
        INSERT INTO public.member_notifications (member_id, kind, title, body)
        VALUES (
            v_post.author_id,
            'comment',
            format('%s replied to "%s"', v_my_name, v_post.title),
             left(v_clean_body, 140)
        );
    END IF;

    RETURN jsonb_build_object(
        'id', v_comm.id,
        'post_id', v_comm.post_id,
        'author_id', v_comm.author_id,
        'author_name', v_my_name,
        'body', v_comm.body,
        'created_at', v_comm.created_at
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_add_comment(text, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_add_comment(text, uuid, text) TO anon, authenticated;

CREATE OR REPLACE FUNCTION public.learner_report_post(
    p_raw_token text,
    p_post_id uuid,
    p_reason text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_clean_reason text;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);
    v_clean_reason := coalesce(nullif(public.sanitize_club_text(p_reason), ''), 'Flagged by club member for steward review');

    UPDATE public.community_posts
       SET moderation_status = 'reported',
           report_reason = v_clean_reason,
           reported_by = v_member_id,
           updated_at = now()
     WHERE id = p_post_id
       AND moderation_status <> 'hidden_by_mod';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND: Post not found.'
            USING ERRCODE = 'P0002';
    END IF;

    RETURN jsonb_build_object('status', 'reported', 'post_id', p_post_id);
END;
$$;

REVOKE ALL ON FUNCTION public.learner_report_post(text, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_report_post(text, uuid, text) TO anon, authenticated;

CREATE OR REPLACE FUNCTION public.learner_manage_session(
    p_raw_token text,
    p_action text,
    p_session_id uuid DEFAULT NULL,
    p_title text DEFAULT '',
    p_scheduled_pkt text DEFAULT '',
    p_focus_topic text DEFAULT '',
    p_external_bbo_note text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_clean_title text;
    v_clean_pkt text;
    v_clean_focus text;
    v_clean_note text;
    v_sess RECORD;
    v_cur_count integer;
    v_new_id uuid;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);

    IF p_action = 'create' THEN
        v_clean_title := public.sanitize_club_text(p_title);
        v_clean_pkt := public.sanitize_club_text(p_scheduled_pkt);
        v_clean_focus := coalesce(nullif(public.sanitize_club_text(p_focus_topic), ''), 'Lesson 1E & 1F Practice');
        v_clean_note := coalesce(nullif(public.sanitize_club_text(p_external_bbo_note), ''), 'Lahore Bridge Club In-App Table & Voice Room');

        IF char_length(v_clean_title) = 0 OR char_length(v_clean_pkt) = 0 THEN
            RAISE EXCEPTION 'VALIDATION_ERROR: Session title and PKT schedule time are required.'
                USING ERRCODE = '22023';
        END IF;

        INSERT INTO public.practice_sessions (
            host_id, title, scheduled_pkt, focus_topic, external_bbo_note, max_players
        ) VALUES (
            v_member_id, v_clean_title, v_clean_pkt, v_clean_focus, v_clean_note, 4
        )
        RETURNING id INTO v_new_id;

        INSERT INTO public.practice_session_rsvps (session_id, member_id)
        VALUES (v_new_id, v_member_id)
        ON CONFLICT (session_id, member_id) DO NOTHING;

        RETURN jsonb_build_object('status', 'created', 'session_id', v_new_id);

    ELSIF p_action = 'toggle_rsvp' THEN
        SELECT ps.id, ps.max_players INTO v_sess
          FROM public.practice_sessions ps
         WHERE ps.id = p_session_id
         LIMIT 1;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'NOT_FOUND: Practice session not found.'
                USING ERRCODE = 'P0002';
        END IF;

        IF EXISTS (
            SELECT 1 FROM public.practice_session_rsvps r
             WHERE r.session_id = p_session_id AND r.member_id = v_member_id
        ) THEN
            DELETE FROM public.practice_session_rsvps
             WHERE session_id = p_session_id AND member_id = v_member_id;
            RETURN jsonb_build_object('status', 'left', 'session_id', p_session_id);
        ELSE
            SELECT count(*)::integer INTO v_cur_count
              FROM public.practice_session_rsvps r
             WHERE r.session_id = p_session_id;

            IF v_cur_count >= v_sess.max_players THEN
                RAISE EXCEPTION 'SESSION_FULL: This practice table is already full (%/% players seated).', v_cur_count, v_sess.max_players
                    USING ERRCODE = '22023';
            END IF;

            INSERT INTO public.practice_session_rsvps (session_id, member_id)
            VALUES (p_session_id, v_member_id);
            RETURN jsonb_build_object('status', 'joined', 'session_id', p_session_id);
        END IF;
    ELSE
        RAISE EXCEPTION 'VALIDATION_ERROR: Unknown session action %.', p_action
            USING ERRCODE = '22023';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.learner_manage_session(text, text, uuid, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_manage_session(text, text, uuid, text, text, text, text) TO anon, authenticated;

CREATE OR REPLACE FUNCTION public.learner_mark_notifications_read(p_raw_token text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_count integer;
BEGIN
    v_member_id := public.validate_learner_token(p_raw_token);

    UPDATE public.member_notifications
       SET is_read = true
     WHERE member_id = v_member_id
       AND is_read = false;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN jsonb_build_object('status', 'ok', 'marked_read_count', v_count);
END;
$$;

REVOKE ALL ON FUNCTION public.learner_mark_notifications_read(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_mark_notifications_read(text) TO anon, authenticated;

-- =============================================================================
-- 10. REPLACED ORGANISER DASHBOARD & STEWARD MODERATION / THRESHOLD RPCS
-- =============================================================================

CREATE OR REPLACE FUNCTION public.organiser_get_dashboard()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_club_settings jsonb;
    v_lessons jsonb;
    v_members jsonb;
    v_reported_posts jsonb;
    v_mistake_queue jsonb;
BEGIN
    v_uid := public.assert_is_organiser();

    SELECT jsonb_build_object(
        'progression_threshold_pct', coalesce(cs.progression_threshold_pct, 80),
        'answer_key_version', coalesce(cs.answer_key_version, 'v2.0-2026-10-27')
    )
    INTO v_club_settings
    FROM public.club_settings cs
    WHERE cs.id = 1;

    v_club_settings := coalesce(v_club_settings, '{"progression_threshold_pct": 80, "answer_key_version": "v2.0-2026-10-27"}'::jsonb);

    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
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
            'validation_status', l.validation_status,
            'private_materials', jsonb_build_object(
                'answer_key_json', coalesce(lpm.answer_key_json, '[]'::jsonb),
                'extra_answer_key_json', coalesce(lpm.extra_answer_key_json, '[]'::jsonb),
                'organiser_source_notes', coalesce(lpm.organiser_source_notes, '')
            )
        ) ORDER BY l.seq_order ASC
    ), '[]'::jsonb)
    INTO v_lessons
    FROM public.lessons l
    LEFT JOIN public.lesson_private_materials lpm ON lpm.lesson_code = l.code;

    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', m.id,
            'name', m.name,
            'email', m.email,
            'interest_status', m.interest_status,
            'availability_pkt', m.availability_pkt,
            'experience', m.experience,
            'last_emailed_date', m.last_emailed_date,
            'follow_up_date', m.follow_up_date,
            'follow_up_check', CASE
                WHEN m.interest_status = 'Not interested' THEN 'Closed'
                WHEN m.follow_up_date IS NULL THEN ''
                WHEN m.follow_up_date <= CURRENT_DATE THEN 'Due'
                ELSE 'Scheduled'
            END,
            'organiser_notes', coalesce(mpn.organiser_notes, ''),
            'questions_next_action', coalesce(mpn.questions_next_action, ''),
            'active_invitation', (
                SELECT jsonb_build_object(
                    'id', li.id,
                    'token_prefix', li.token_prefix,
                    'created_at', li.created_at,
                    'expires_at', li.expires_at,
                    'revoked_at', li.revoked_at,
                    'last_used_at', li.last_used_at,
                    'is_active', (li.revoked_at IS NULL AND li.expires_at > now())
                )
                FROM public.learner_invitations li
                WHERE li.member_id = m.id
                ORDER BY li.created_at DESC
                LIMIT 1
            ),
            'assignments', coalesce((
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'id', la.id,
                        'lesson_code', la.lesson_code,
                        'status', la.status,
                        'released_at', la.released_at,
                        'finished_at', la.finished_at,
                        'submissions', coalesce((
                            SELECT jsonb_agg(
                                jsonb_build_object(
                                    'id', s.id,
                                    'version_number', s.version_number,
                                    'status', s.status,
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
                        ), '[]'::jsonb)
                    ) ORDER BY (
                        CASE la.lesson_code WHEN '1E' THEN 1 WHEN '1F' THEN 2 WHEN '1G' THEN 3 ELSE 9 END
                    ) ASC
                )
                FROM public.lesson_assignments la
                WHERE la.member_id = m.id
            ), '[]'::jsonb)
        ) ORDER BY (CASE WHEN m.interest_status = 'Organiser' THEN 0 ELSE 1 END), m.created_at ASC
    ), '[]'::jsonb)
    INTO v_members
    FROM public.members m
    LEFT JOIN public.member_private_notes mpn ON mpn.member_id = m.id;

    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', rp.id,
            'author_id', rp.author_id,
            'author_name', coalesce(am.name, 'Club Member'),
            'category', rp.category,
            'lesson_code', rp.lesson_code,
            'title', rp.title,
            'body', rp.body,
            'moderation_status', rp.moderation_status,
            'report_reason', rp.report_reason,
            'reported_by', rp.reported_by,
            'created_at', rp.created_at
        ) ORDER BY rp.updated_at DESC
    ), '[]'::jsonb)
    INTO v_reported_posts
    FROM public.community_posts rp
    LEFT JOIN public.members am ON am.id = rp.author_id
    WHERE rp.moderation_status = 'reported';

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
        )
    ), '[]'::jsonb)
    INTO v_mistake_queue
    FROM public.learner_mistake_queue mq;

    RETURN jsonb_build_object(
        'organiser_uid', v_uid,
        'club_settings', v_club_settings,
        'lessons', v_lessons,
        'members', v_members,
        'reported_posts', v_reported_posts,
        'mistake_queue', v_mistake_queue
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_get_dashboard() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_get_dashboard() TO authenticated;

CREATE OR REPLACE FUNCTION public.organiser_moderate_post(
    p_post_id uuid,
    p_decision text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_new_status text;
BEGIN
    v_uid := public.assert_is_organiser();

    IF p_decision NOT IN ('hide', 'dismiss') THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Moderation decision must be hide or dismiss.'
            USING ERRCODE = '22023';
    END IF;

    v_new_status := CASE WHEN p_decision = 'hide' THEN 'hidden_by_mod' ELSE 'visible' END;

    UPDATE public.community_posts
       SET moderation_status = v_new_status,
           report_reason = CASE WHEN p_decision = 'dismiss' THEN '' ELSE report_reason END,
           updated_at = now()
     WHERE id = p_post_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND: Community post not found.'
            USING ERRCODE = 'P0002';
    END IF;

    RETURN jsonb_build_object(
        'status', 'ok',
        'post_id', p_post_id,
        'moderation_status', v_new_status
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_moderate_post(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_moderate_post(uuid, text) TO authenticated;

CREATE OR REPLACE FUNCTION public.organiser_update_threshold(
    p_threshold_pct integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
BEGIN
    v_uid := public.assert_is_organiser();

    IF p_threshold_pct IS NULL OR p_threshold_pct < 50 OR p_threshold_pct > 100 THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Progression threshold must be between 50% and 100%.'
            USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.club_settings (id, progression_threshold_pct, updated_at)
    VALUES (1, p_threshold_pct, now())
    ON CONFLICT (id) DO UPDATE
       SET progression_threshold_pct = EXCLUDED.progression_threshold_pct,
           updated_at = now();

    RETURN jsonb_build_object('progression_threshold_pct', p_threshold_pct);
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_update_threshold(integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_update_threshold(integer) TO authenticated;

-- Also update organiser_review_submission so learner receives an in-app notification on steward reply
CREATE OR REPLACE FUNCTION public.organiser_review_submission(
    p_submission_id uuid,
    p_feedback text,
    p_question_resolved boolean DEFAULT true,
    p_assignment_status text DEFAULT 'Reviewed'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_sub RECORD;
    v_fb_id uuid;
BEGIN
    v_uid := public.assert_is_organiser();

    IF char_length(trim(coalesce(p_feedback, ''))) = 0 THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Feedback text cannot be empty.'
            USING ERRCODE = '22023';
    END IF;

    IF p_assignment_status NOT IN ('Working on it', 'Needs help', 'Reviewed', 'Finished', 'Paused') THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Invalid assignment review status.'
            USING ERRCODE = '22023';
    END IF;

    SELECT s.id, s.assignment_id, s.member_id, s.lesson_code, s.status
      INTO v_sub
      FROM public.submissions s
     WHERE s.id = p_submission_id
     LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND: Submission not found.'
            USING ERRCODE = 'P0002';
    END IF;

    IF v_sub.status = 'draft' THEN
        RAISE EXCEPTION 'INVALID_STATE: Cannot formally review an unsubmitted learner draft.'
            USING ERRCODE = '22023';
    END IF;

    UPDATE public.submissions
       SET status = 'reviewed',
           reviewed_at = now(),
           updated_at = now()
     WHERE id = p_submission_id;

    INSERT INTO public.submission_feedback (
        submission_id, assignment_id, member_id, organiser_feedback, question_resolved, created_by
    ) VALUES (
        v_sub.id, v_sub.assignment_id, v_sub.member_id, trim(p_feedback), coalesce(p_question_resolved, true), v_uid
    )
    RETURNING id INTO v_fb_id;

    UPDATE public.lesson_assignments
       SET status = p_assignment_status,
           finished_at = CASE
               WHEN p_assignment_status = 'Finished' THEN coalesce(finished_at, CURRENT_DATE)
               ELSE finished_at
           END,
           updated_at = now()
     WHERE id = v_sub.assignment_id;

    INSERT INTO public.member_notifications (member_id, kind, title, body)
    VALUES (
        v_sub.member_id,
        'feedback',
        format('Steward Reply on Lesson %s', v_sub.lesson_code),
        left(trim(p_feedback), 140)
    );

    RETURN jsonb_build_object(
        'feedback_id', v_fb_id,
        'submission_id', p_submission_id,
        'assignment_status', p_assignment_status,
        'reviewed_at', now()
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_review_submission(uuid, text, boolean, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_review_submission(uuid, text, boolean, text) TO authenticated;

-- Also update organiser_release_lesson to enforce validation_status = 'validated'
CREATE OR REPLACE FUNCTION public.organiser_release_lesson(
    p_member_id uuid,
    p_lesson_code text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_target_lesson RECORD;
    v_prev_code text;
    v_prev_assignment RECORD;
    v_has_reviewed_sub boolean;
    v_assignment_id uuid;
BEGIN
    v_uid := public.assert_is_organiser();

    IF p_lesson_code NOT IN ('1E', '1F', '1G') THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Invalid lesson code %. Must be 1E, 1F, or 1G.', p_lesson_code
            USING ERRCODE = '22023';
    END IF;

    SELECT l.code, l.is_draft, l.validation_status, l.hands_json, l.instructions
      INTO v_target_lesson
      FROM public.lessons l
     WHERE l.code = p_lesson_code
     LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND: Target lesson % does not exist.', p_lesson_code
            USING ERRCODE = 'P0002';
    END IF;

    IF v_target_lesson.is_draft IS TRUE OR v_target_lesson.validation_status <> 'validated' THEN
        RAISE EXCEPTION 'LESSON_NOT_READY: Cannot release Lesson % because it is marked as an unvalidated draft (is_draft = %, validation_status = %). Populate and validate the lesson first.',
            p_lesson_code, v_target_lesson.is_draft, v_target_lesson.validation_status
            USING ERRCODE = '22023';
    END IF;

    IF jsonb_typeof(v_target_lesson.hands_json) <> 'array'
       OR jsonb_array_length(v_target_lesson.hands_json) = 0
       OR char_length(trim(coalesce(v_target_lesson.instructions, ''))) = 0 THEN
        RAISE EXCEPTION 'LESSON_EMPTY: Cannot release Lesson % because it has no usable exercise hands or instructions.', p_lesson_code
            USING ERRCODE = '22023';
    END IF;

    IF p_lesson_code = '1F' THEN
        v_prev_code := '1E';
    ELSIF p_lesson_code = '1G' THEN
        v_prev_code := '1F';
    ELSE
        v_prev_code := NULL;
    END IF;

    IF v_prev_code IS NOT NULL THEN
        SELECT la.id, la.status
          INTO v_prev_assignment
          FROM public.lesson_assignments la
         WHERE la.member_id = p_member_id
           AND la.lesson_code = v_prev_code
         LIMIT 1;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'PREREQUISITE_NOT_MET: Cannot release Lesson % before Lesson % has been assigned.', p_lesson_code, v_prev_code
                USING ERRCODE = '22023';
        END IF;

        IF v_prev_assignment.status NOT IN ('Reviewed', 'Finished') THEN
            RAISE EXCEPTION 'PREREQUISITE_NOT_MET: Cannot release Lesson % until Lesson % has been reviewed or passed (current status: %).',
                p_lesson_code, v_prev_code, v_prev_assignment.status
                USING ERRCODE = '22023';
        END IF;

        SELECT EXISTS (
            SELECT 1
              FROM public.submissions s
             WHERE s.assignment_id = v_prev_assignment.id
               AND s.status = 'reviewed'
               AND s.reviewed_at IS NOT NULL
        ) INTO v_has_reviewed_sub;

        IF NOT v_has_reviewed_sub THEN
            RAISE EXCEPTION 'PREREQUISITE_NOT_MET: Cannot release Lesson % until at least one learner submission for Lesson % has been reviewed.',
                p_lesson_code, v_prev_code
                USING ERRCODE = '22023';
        END IF;

        UPDATE public.lesson_assignments
           SET status = 'Finished',
               finished_at = coalesce(finished_at, CURRENT_DATE),
               updated_at = now()
         WHERE id = v_prev_assignment.id;
    END IF;

    INSERT INTO public.lesson_assignments (
        member_id, lesson_code, status, released_at, released_by
    ) VALUES (
        p_member_id, p_lesson_code, 'Not started', now(), v_uid
    )
    ON CONFLICT (member_id, lesson_code) DO UPDATE
       SET updated_at = now()
    RETURNING id INTO v_assignment_id;

    RETURN jsonb_build_object(
        'assignment_id', v_assignment_id,
        'member_id', p_member_id,
        'lesson_code', p_lesson_code,
        'status', 'Not started',
        'released_at', now()
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_release_lesson(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_release_lesson(uuid, text) TO authenticated;

-- Also update organiser_update_lesson_material so validation_status is synced with is_draft
CREATE OR REPLACE FUNCTION public.organiser_update_lesson_material(
    p_lesson_code text,
    p_title text,
    p_subtitle text,
    p_instructions text,
    p_hands_json jsonb,
    p_is_draft boolean,
    p_answer_key_json jsonb,
    p_organiser_source_notes text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_final_hands jsonb;
    v_final_instr text;
    v_final_draft boolean;
BEGIN
    v_uid := public.assert_is_organiser();

    SELECT coalesce(p_hands_json, l.hands_json),
           coalesce(p_instructions, l.instructions),
           coalesce(p_is_draft, l.is_draft)
      INTO v_final_hands, v_final_instr, v_final_draft
      FROM public.lessons l
     WHERE l.code = p_lesson_code;

    IF v_final_draft IS FALSE THEN
        IF jsonb_typeof(v_final_hands) <> 'array'
           OR jsonb_array_length(v_final_hands) = 0
           OR char_length(trim(coalesce(v_final_instr, ''))) = 0 THEN
            RAISE EXCEPTION 'LESSON_EMPTY: Cannot publish Lesson % (is_draft = false) while hands or instructions are empty.', p_lesson_code
                USING ERRCODE = '22023';
        END IF;
    END IF;

    UPDATE public.lessons
       SET title = coalesce(p_title, title),
           subtitle = coalesce(p_subtitle, subtitle),
           instructions = coalesce(p_instructions, instructions),
           hands_json = coalesce(p_hands_json, hands_json),
           is_draft = v_final_draft,
           validation_status = CASE WHEN v_final_draft THEN 'draft' ELSE 'validated' END,
           updated_at = now()
     WHERE code = p_lesson_code;

    INSERT INTO public.lesson_private_materials (
        lesson_code, answer_key_json, organiser_source_notes, updated_at
    ) VALUES (
        p_lesson_code, coalesce(p_answer_key_json, '[]'::jsonb), coalesce(p_organiser_source_notes, ''), now()
    )
    ON CONFLICT (lesson_code) DO UPDATE
       SET answer_key_json = EXCLUDED.answer_key_json,
           organiser_source_notes = EXCLUDED.organiser_source_notes,
           updated_at = now();

    RETURN jsonb_build_object('lesson_code', p_lesson_code, 'updated_at', now());
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_update_lesson_material(text, text, text, text, jsonb, boolean, jsonb, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_update_lesson_material(text, text, text, text, jsonb, boolean, jsonb, text) TO authenticated;

COMMIT;

-- =============================================================================
-- MIGRATION V3: DURABLE LEARNER ACCOUNTS, LEGACY PROGRESS LINKING,
-- CONCURRENCY-SAFE SUBMISSIONS & SESSIONS, PRACTICE READINESS GATE,
-- FRIENDS-ONLY DIRECT MESSAGING, STUDY GROUPS & ATOMIC FOUNDING 100 ALLOCATION
-- =============================================================================
-- Safe, idempotent migration building on schema.sql + migration_v2_club_academy.sql.
-- Fixes all 3 source-review concurrency/authorization findings and adds:
-- 1. Practice hand authorization & readiness gate (`public.learner_check_practice_hand`
--    verifies active lesson assignment + published/validated status before reading keys).
-- 2. Explicit, retry-safe `join` and `leave` session actions (`public.learner_manage_session`)
--    using row-level locking (`SELECT ... FOR UPDATE`) for atomic capacity enforcement.
-- 3. Durable `client_request_id` deduplication and row-locked (`FOR UPDATE`) version
--    allocation in `public.learner_submit_and_grade_lesson` and `public.learner_submit_work`.
-- 4. Durable cross-device Supabase Auth learner accounts (`members.auth_user_id`,
--    `public.resolve_learner_identity`, `public.learner_claim_or_register_account`)
--    preserving invitation-token access and linking existing learner progress seamlessly.
-- 5. Atomic Founding 100 Lifetime Premium allocation (`public.allocate_founding_membership_if_eligible`)
--    serialized via transaction advisory lock (`pg_advisory_xact_lock(77100)`) with a hard cap of 100.
-- 6. Friends-only 1-to-1 Direct Messaging (`public.direct_messages`) enforcing accepted
--    friendship and mutual block checks, plus study groups (`public.study_groups`).
-- 7. Removal of external third-party competitor competitor links/defaults.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. SCHEMA EXTENSIONS FOR ACCOUNTS, FOUNDING 100, SUBMISSIONS, DMS & GROUPS
-- -----------------------------------------------------------------------------

ALTER TABLE public.members
    ADD COLUMN IF NOT EXISTS auth_user_id uuid UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS email_verified_at timestamptz DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS membership_tier text NOT NULL DEFAULT 'standard'
        CHECK (membership_tier IN ('standard', 'founding_100')),
    ADD COLUMN IF NOT EXISTS founder_number integer UNIQUE
        CHECK (founder_number IS NULL OR (founder_number BETWEEN 1 AND 100)),
    ADD COLUMN IF NOT EXISTS founder_granted_at timestamptz DEFAULT NULL;

ALTER TABLE public.club_settings
    ADD COLUMN IF NOT EXISTS founding_100_limit integer NOT NULL DEFAULT 100
        CHECK (founding_100_limit BETWEEN 1 AND 100),
    ADD COLUMN IF NOT EXISTS founding_100_benefits_json jsonb NOT NULL DEFAULT
        '["Lifetime Premium Club Membership (Founding 100)", "All current & future Dennis''s Method interactive lessons & printable editions", "Personalised mistake-queue revision & printable practice collections", "Friends-only Direct Messaging & Study Groups", "Priority seats in Guided & 4-Human Multiplayer club tables"]'::jsonb;

UPDATE public.club_settings
   SET answer_key_version = 'v3.0-founding100',
       founding_100_limit = coalesce(founding_100_limit, 100),
       updated_at = now()
 WHERE id = 1;

ALTER TABLE public.submissions
    ADD COLUMN IF NOT EXISTS client_request_id text DEFAULT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_submissions_assignment_client_req
    ON public.submissions (assignment_id, client_request_id)
    WHERE client_request_id IS NOT NULL;

-- Remove BBO competitor references from practice_sessions default & existing rows
ALTER TABLE public.practice_sessions
    ALTER COLUMN external_bbo_note SET DEFAULT 'Lahore Bridge Club In-App Table & Voice Room';

UPDATE public.practice_sessions
   SET external_bbo_note = 'Lahore Bridge Club In-App Table & Voice Room'
 WHERE external_bbo_note ILIKE '%clubtable%'
    OR external_bbo_note ILIKE '%BBO%';

-- Friends-Only 1-to-1 Direct Messages table
CREATE TABLE IF NOT EXISTS public.direct_messages (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    sender_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    recipient_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    body text NOT NULL CHECK (char_length(trim(body)) BETWEEN 1 AND 2000),
    client_message_id text DEFAULT NULL,
    read_at timestamptz DEFAULT NULL,
    moderation_status text NOT NULL DEFAULT 'visible'
        CHECK (moderation_status IN ('visible', 'reported', 'hidden_by_mod')),
    report_reason text NOT NULL DEFAULT '',
    reported_by uuid REFERENCES public.members(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (sender_id <> recipient_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_direct_messages_sender_client_msg
    ON public.direct_messages (sender_id, client_message_id)
    WHERE client_message_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_direct_messages_participants
    ON public.direct_messages (sender_id, recipient_id, created_at DESC);

-- Study Groups & Membership tables
CREATE TABLE IF NOT EXISTS public.study_groups (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    creator_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(trim(name)) BETWEEN 1 AND 120),
    focus_lesson text NOT NULL DEFAULT '1E' CHECK (focus_lesson IN ('1E', '1F', '1G')),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 600),
    meeting_time_pkt text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.study_group_members (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    group_id uuid NOT NULL REFERENCES public.study_groups(id) ON DELETE CASCADE,
    member_id uuid NOT NULL REFERENCES public.members(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (group_id, member_id)
);

ALTER TABLE public.direct_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.direct_messages FORCE ROW LEVEL SECURITY;
ALTER TABLE public.study_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.study_groups FORCE ROW LEVEL SECURITY;
ALTER TABLE public.study_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.study_group_members FORCE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, anon, authenticated;

-- Update immutability trigger so client_request_id and grading_json are immutable once submitted
CREATE OR REPLACE FUNCTION public.enforce_submission_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF OLD.status IN ('submitted', 'reviewed') THEN
        IF NEW.answers_json IS DISTINCT FROM OLD.answers_json
           OR NEW.learner_questions IS DISTINCT FROM OLD.learner_questions
           OR NEW.version_number IS DISTINCT FROM OLD.version_number
           OR NEW.assignment_id IS DISTINCT FROM OLD.assignment_id
           OR NEW.member_id IS DISTINCT FROM OLD.member_id
           OR NEW.lesson_code IS DISTINCT FROM OLD.lesson_code
           OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at
           OR (OLD.client_request_id IS NOT NULL AND NEW.client_request_id IS DISTINCT FROM OLD.client_request_id)
           OR (OLD.grading_json IS NOT NULL AND NEW.grading_json IS DISTINCT FROM OLD.grading_json) THEN
            RAISE EXCEPTION 'IMMUTABLE_SUBMISSION: Submitted work and backend grading cannot be overwritten. Submit a new attempt version instead.'
                USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

-- -----------------------------------------------------------------------------
-- 2. UNIFIED LEARNER IDENTITY RESOLVER & ATOMIC FOUNDING 100 ALLOCATOR
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
-- 3. UPGRADED LEARNER PORTAL RPC (`public.learner_get_portal`)
--    Supports both durable `auth.uid()` accounts and invitation tokens, and
--    returns Founding 100 status, Direct Messages, and Study Groups.
-- -----------------------------------------------------------------------------
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

-- -----------------------------------------------------------------------------
-- 4. CONCURRENCY-SAFE LESSON SUBMISSION & GRADING (`client_request_id` + `FOR UPDATE`)
-- -----------------------------------------------------------------------------

-- Upgrade learner_save_draft to lock the assignment row FOR UPDATE
CREATE OR REPLACE FUNCTION public.learner_save_draft(
    p_raw_token text,
    p_lesson_code text,
    p_answers_json jsonb,
    p_learner_questions text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_assignment RECORD;
    v_draft_id uuid;
    v_next_ver integer;
    v_new_status text;
BEGIN
    v_member_id := public.resolve_learner_identity(p_raw_token);

    -- Row-level lock serializes concurrent draft/submit operations for this assignment
    SELECT la.id, la.status
      INTO v_assignment
      FROM public.lesson_assignments la
     WHERE la.member_id = v_member_id
       AND la.lesson_code = p_lesson_code
       FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_ASSIGNED: This lesson has not been released to you.'
            USING ERRCODE = '42501';
    END IF;

    IF v_assignment.status = 'Paused' THEN
        RAISE EXCEPTION 'ASSIGNMENT_PAUSED: This lesson assignment is currently paused.'
            USING ERRCODE = '42501';
    END IF;

    SELECT s.id, s.version_number
      INTO v_draft_id, v_next_ver
      FROM public.submissions s
     WHERE s.assignment_id = v_assignment.id
       AND s.member_id = v_member_id
       AND s.status = 'draft'
     ORDER BY s.version_number DESC
     LIMIT 1;

    IF v_draft_id IS NOT NULL THEN
        UPDATE public.submissions
           SET answers_json = coalesce(p_answers_json, '{}'::jsonb),
               learner_questions = coalesce(p_learner_questions, ''),
               updated_at = now()
         WHERE id = v_draft_id;
    ELSE
        SELECT coalesce(max(s.version_number), 0) + 1
          INTO v_next_ver
          FROM public.submissions s
         WHERE s.assignment_id = v_assignment.id;

        INSERT INTO public.submissions (
            assignment_id, member_id, lesson_code, version_number, status, answers_json, learner_questions
        ) VALUES (
            v_assignment.id, v_member_id, p_lesson_code, v_next_ver, 'draft',
            coalesce(p_answers_json, '{}'::jsonb), coalesce(p_learner_questions, '')
        )
        RETURNING id INTO v_draft_id;
    END IF;

    IF v_assignment.status NOT IN ('Reviewed', 'Finished', 'Submitted') THEN
        v_new_status := CASE
            WHEN char_length(trim(coalesce(p_learner_questions, ''))) > 0 THEN 'Needs help'
            ELSE 'Working on it'
        END;
        UPDATE public.lesson_assignments
           SET status = v_new_status,
               updated_at = now()
         WHERE id = v_assignment.id;
    END IF;

    RETURN jsonb_build_object(
        'submission_id', v_draft_id,
        'version_number', v_next_ver,
        'status', 'draft',
        'updated_at', now()
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_save_draft(text, text, jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_save_draft(text, text, jsonb, text) TO anon, authenticated;

-- Upgrade learner_submit_work with FOR UPDATE lock and client_request_id deduplication
DROP FUNCTION IF EXISTS public.learner_submit_work(text, text, jsonb, text);

CREATE OR REPLACE FUNCTION public.learner_submit_work(
    p_raw_token text,
    p_lesson_code text,
    p_answers_json jsonb,
    p_learner_questions text DEFAULT '',
    p_client_request_id text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_assignment RECORD;
    v_clean_req_id text;
    v_existing RECORD;
    v_sub_id uuid;
    v_ver integer;
    v_new_assignment_status text;
BEGIN
    v_member_id := public.resolve_learner_identity(p_raw_token);
    v_clean_req_id := nullif(trim(coalesce(p_client_request_id, '')), '');

    -- Row-level lock on assignment prevents race conditions on version_number and retries
    SELECT la.id, la.status
      INTO v_assignment
      FROM public.lesson_assignments la
     WHERE la.member_id = v_member_id
       AND la.lesson_code = p_lesson_code
       FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_ASSIGNED: This lesson has not been released to you.'
            USING ERRCODE = '42501';
    END IF;

    IF v_assignment.status = 'Paused' THEN
        RAISE EXCEPTION 'ASSIGNMENT_PAUSED: This lesson assignment is currently paused.'
            USING ERRCODE = '42501';
    END IF;

    IF v_clean_req_id IS NOT NULL THEN
        SELECT s.id, s.version_number, s.status, s.submitted_at
          INTO v_existing
          FROM public.submissions s
         WHERE s.assignment_id = v_assignment.id
           AND s.client_request_id = v_clean_req_id
         LIMIT 1;

        IF FOUND THEN
            RETURN jsonb_build_object(
                'submission_id', v_existing.id,
                'version_number', v_existing.version_number,
                'status', v_existing.status,
                'client_request_id', v_clean_req_id,
                'deduplicated', true,
                'submitted_at', v_existing.submitted_at
            );
        END IF;
    END IF;

    SELECT s.id, s.version_number
      INTO v_sub_id, v_ver
      FROM public.submissions s
     WHERE s.assignment_id = v_assignment.id
       AND s.member_id = v_member_id
       AND s.status = 'draft'
     ORDER BY s.version_number DESC
     LIMIT 1;

    IF v_sub_id IS NOT NULL THEN
        UPDATE public.submissions
           SET answers_json = coalesce(p_answers_json, '{}'::jsonb),
               learner_questions = coalesce(p_learner_questions, ''),
               client_request_id = v_clean_req_id,
               status = 'submitted',
               submitted_at = now(),
               updated_at = now()
         WHERE id = v_sub_id;
    ELSE
        SELECT coalesce(max(s.version_number), 0) + 1
          INTO v_ver
          FROM public.submissions s
         WHERE s.assignment_id = v_assignment.id;

        INSERT INTO public.submissions (
            assignment_id, member_id, lesson_code, version_number, status,
            client_request_id, answers_json, learner_questions, submitted_at
        ) VALUES (
            v_assignment.id, v_member_id, p_lesson_code, v_ver, 'submitted',
            v_clean_req_id, coalesce(p_answers_json, '{}'::jsonb), coalesce(p_learner_questions, ''), now()
        )
        RETURNING id INTO v_sub_id;
    END IF;

    v_new_assignment_status := CASE
        WHEN char_length(trim(coalesce(p_learner_questions, ''))) > 0 THEN 'Needs help'
        ELSE 'Submitted'
    END;

    UPDATE public.lesson_assignments
       SET status = v_new_assignment_status,
           updated_at = now()
     WHERE id = v_assignment.id;

    RETURN jsonb_build_object(
        'submission_id', v_sub_id,
        'version_number', v_ver,
        'status', 'submitted',
        'client_request_id', v_clean_req_id,
        'deduplicated', false,
        'assignment_status', v_new_assignment_status,
        'submitted_at', now()
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_submit_work(text, text, jsonb, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_submit_work(text, text, jsonb, text, text) TO anon, authenticated;

-- Upgrade learner_submit_and_grade_lesson with:
-- 1. Row-level lock (`SELECT ... FROM public.lesson_assignments ... FOR UPDATE`)
-- 2. Durable `p_client_request_id` idempotency check (plus 3s payload fallback)
-- 3. Transaction-safe `version_number` allocation under the assignment lock
DROP FUNCTION IF EXISTS public.learner_submit_and_grade_lesson(text, text, jsonb, text);

CREATE OR REPLACE FUNCTION public.learner_submit_and_grade_lesson(
    p_raw_token text,
    p_lesson_code text,
    p_answers_json jsonb,
    p_learner_questions text DEFAULT '',
    p_client_request_id text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_assignment RECORD;
    v_clean_req_id text;
    v_existing_req_sub RECORD;
    v_lesson RECORD;
    v_key_array jsonb;
    v_threshold integer;
    v_key_ver text;
    v_item jsonb;
    v_hand_num text;
    v_ans jsonb;
    v_exp_hcp integer;
    v_exp_dist integer;
    v_exp_tcp integer;
    v_exp_bid text;
    v_user_hcp integer;
    v_user_dist integer;
    v_user_bid text;
    v_hcp_ok boolean;
    v_dist_ok boolean;
    v_bid_ok boolean;
    v_total_components integer := 0;
    v_earned_components integer := 0;
    v_hcp_correct integer := 0;
    v_dist_correct integer := 0;
    v_bid_correct integer := 0;
    v_hand_count integer := 0;
    v_breakdown jsonb := '[]'::jsonb;
    v_diag text;
    v_missed jsonb;
    v_score_pct integer;
    v_passed boolean;
    v_sub_id uuid;
    v_ver integer;
    v_latest_sub RECORD;
    v_next_code text;
    v_next_lesson RECORD;
    v_unlocked_next text := NULL;
    v_next_status_note text := '';
    v_grading_payload jsonb;
    v_clean_q text;
    v_has_q boolean;
    v_final_sub_status text;
BEGIN
    v_member_id := public.resolve_learner_identity(p_raw_token);
    v_clean_q := public.sanitize_club_text(p_learner_questions);
    v_has_q := char_length(v_clean_q) > 0;
    v_clean_req_id := nullif(trim(coalesce(p_client_request_id, '')), '');

    -- Acquire exclusive row-level lock on this learner's assignment to serialize
    -- concurrent requests and guarantee unique sequential attempt version numbers
    SELECT la.id, la.status
      INTO v_assignment
      FROM public.lesson_assignments la
     WHERE la.member_id = v_member_id
       AND la.lesson_code = p_lesson_code
       FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_ASSIGNED: Lesson % has not been unlocked for your account.', p_lesson_code
            USING ERRCODE = '42501';
    END IF;

    IF v_assignment.status = 'Paused' THEN
        RAISE EXCEPTION 'ASSIGNMENT_PAUSED: This lesson assignment is currently paused.'
            USING ERRCODE = '42501';
    END IF;

    -- 1. Durable client_request_id idempotency check (retry-safe across any network delay)
    IF v_clean_req_id IS NOT NULL THEN
        SELECT s.id, s.version_number, s.status, s.grading_json
          INTO v_existing_req_sub
          FROM public.submissions s
         WHERE s.assignment_id = v_assignment.id
           AND s.client_request_id = v_clean_req_id
         LIMIT 1;

        IF FOUND THEN
            RETURN jsonb_build_object(
                'submission_id', v_existing_req_sub.id,
                'version_number', v_existing_req_sub.version_number,
                'status', v_existing_req_sub.status,
                'grading', v_existing_req_sub.grading_json,
                'client_request_id', v_clean_req_id,
                'deduplicated', true
            );
        END IF;
    END IF;

    -- 2. Fallback rapid double-click check when client_request_id was omitted
    SELECT s.id, s.version_number, s.status, s.answers_json, s.learner_questions, s.grading_json, s.submitted_at
      INTO v_latest_sub
      FROM public.submissions s
     WHERE s.assignment_id = v_assignment.id
       AND s.member_id = v_member_id
       AND s.status <> 'draft'
     ORDER BY s.version_number DESC
     LIMIT 1;

    IF v_clean_req_id IS NULL
       AND FOUND
       AND v_latest_sub.answers_json = coalesce(p_answers_json, '{}'::jsonb)
       AND v_latest_sub.learner_questions = v_clean_q
       AND v_latest_sub.submitted_at >= (now() - interval '3 seconds') THEN
        RETURN jsonb_build_object(
            'submission_id', v_latest_sub.id,
            'version_number', v_latest_sub.version_number,
            'status', v_latest_sub.status,
            'grading', v_latest_sub.grading_json,
            'deduplicated', true
        );
    END IF;

    SELECT l.code, l.is_draft, l.validation_status, l.hands_json
      INTO v_lesson
      FROM public.lessons l
     WHERE l.code = p_lesson_code;

    IF NOT FOUND OR v_lesson.is_draft OR v_lesson.validation_status <> 'validated' THEN
        RAISE EXCEPTION 'LESSON_NOT_VALIDATED: Lesson % is not published for automated grading.', p_lesson_code
            USING ERRCODE = '22023';
    END IF;

    SELECT lpm.answer_key_json INTO v_key_array
      FROM public.lesson_private_materials lpm
     WHERE lpm.lesson_code = p_lesson_code;

    SELECT cs.progression_threshold_pct, cs.answer_key_version
      INTO v_threshold, v_key_ver
      FROM public.club_settings cs
     WHERE cs.id = 1;

    v_threshold := coalesce(v_threshold, 80);
    v_key_ver := coalesce(v_key_ver, 'v3.0-founding100');

    FOR v_item IN SELECT * FROM jsonb_array_elements(v_key_array)
    LOOP
        v_hand_count := v_hand_count + 1;
        v_hand_num := (v_item->>'hand_number');
        v_exp_hcp := (v_item->>'hcp')::integer;
        v_exp_dist := (v_item->>'dist_pts')::integer;
        v_exp_tcp := (v_item->>'tcp')::integer;
        v_exp_bid := (v_item->>'recommended_bid');

        v_ans := coalesce(p_answers_json->v_hand_num, '{}'::jsonb);
        BEGIN
            v_user_hcp := nullif(regexp_replace(coalesce(v_ans->>'hcp', v_ans->>'tcp', ''), '[^0-9-]', '', 'g'), '')::integer;
        EXCEPTION WHEN OTHERS THEN
            v_user_hcp := NULL;
        END;
        BEGIN
            v_user_dist := nullif(regexp_replace(coalesce(v_ans->>'dist_pts', '0'), '[^0-9-]', '', 'g'), '')::integer;
        EXCEPTION WHEN OTHERS THEN
            v_user_dist := NULL;
        END;
        v_user_bid := trim(coalesce(v_ans->>'bid', ''));
        IF upper(v_user_bid) IN ('P', 'PASS') THEN v_user_bid := 'Pass'; END IF;
        v_user_bid := replace(replace(replace(replace(upper(v_user_bid), 'PASS', 'Pass'), 'S', '♠'), 'H', '♥'), 'D', '♦');
        v_user_bid := replace(v_user_bid, 'C', '♣');

        v_hcp_ok := (v_user_hcp IS NOT NULL AND v_user_hcp = v_exp_hcp);
        v_dist_ok := (v_user_dist IS NOT NULL AND v_user_dist = v_exp_dist);
        v_bid_ok := (v_user_bid = v_exp_bid);

        v_total_components := v_total_components + 3;
        IF v_hcp_ok THEN v_earned_components := v_earned_components + 1; v_hcp_correct := v_hcp_correct + 1; END IF;
        IF v_dist_ok THEN v_earned_components := v_earned_components + 1; v_dist_correct := v_dist_correct + 1; END IF;
        IF v_bid_ok THEN v_earned_components := v_earned_components + 1; v_bid_correct := v_bid_correct + 1; END IF;

        v_diag := '';
        v_missed := '[]'::jsonb;

        IF NOT v_hcp_ok THEN
            v_missed := v_missed || '["honour_counting"]'::jsonb;
            IF abs(coalesce(v_user_hcp, -99) - v_exp_hcp) = 1 THEN
                v_diag := v_diag || format('Jack counted incorrectly: your HCP (%s) is off by 1 point from %s HCP (remember Ace=4, King=3, Queen=2, Jack=1). ', coalesce(v_user_hcp::text, 'blank'), v_exp_hcp);
            ELSE
                v_diag := v_diag || format('Honour count: expected %s HCP (A=4, K=3, Q=2, J=1), you entered %s. ', v_exp_hcp, coalesce(v_user_hcp::text, 'blank'));
            END IF;
        END IF;

        IF NOT v_dist_ok THEN
            v_missed := v_missed || '["distribution", "fit_recognition"]'::jsonb;
            IF v_hcp_ok AND v_exp_dist = 1 AND coalesce(v_user_dist, 0) = 0 THEN
                v_diag := v_diag || format('Honour points (%s HCP) are correct, but a +%s doubleton distribution point was omitted with 3+ card heart support. ', v_exp_hcp, v_exp_dist);
            ELSIF v_exp_dist = 0 AND coalesce(v_user_dist, 0) > 0 THEN
                v_diag := v_diag || 'Distribution points should be 0 here (either flat 4-3-3-3 shape or fewer than 3 hearts so no heart fit). ';
            ELSE
                v_diag := v_diag || format('Expected %s distribution points, you entered %s. ', v_exp_dist, coalesce(v_user_dist::text, 'blank'));
            END IF;
        END IF;

        IF NOT v_bid_ok THEN
            v_missed := v_missed || '["response_selection"]'::jsonb;
            v_diag := v_diag || format('Expected bid %s (%s), you chose %s.', v_exp_bid, coalesce(v_item->>'notes', ''), coalesce(nullif(v_user_bid, ''), 'blank'));
        END IF;

        IF v_hcp_ok AND v_dist_ok AND v_bid_ok THEN
            v_diag := format('Spot on! %s HCP + %s Dist = %s TCP -> %s. %s', v_exp_hcp, v_exp_dist, v_exp_tcp, v_exp_bid, coalesce(v_item->>'notes', ''));
            UPDATE public.learner_mistake_queue
               SET mastered = true, last_diagnostic = v_diag, updated_at = now()
             WHERE member_id = v_member_id AND lesson_code = p_lesson_code AND hand_number = v_hand_num::integer;
        ELSE
            INSERT INTO public.learner_mistake_queue (
                member_id, lesson_code, hand_number, missed_skills, last_diagnostic, times_missed, mastered, updated_at
            ) VALUES (
                v_member_id, p_lesson_code, v_hand_num::integer, v_missed, trim(v_diag), 1, false, now()
            )
            ON CONFLICT (member_id, lesson_code, hand_number) DO UPDATE
               SET missed_skills = EXCLUDED.missed_skills,
                   last_diagnostic = EXCLUDED.last_diagnostic,
                   times_missed = public.learner_mistake_queue.times_missed + 1,
                   mastered = false,
                   updated_at = now();
        END IF;

        v_breakdown := v_breakdown || jsonb_build_array(jsonb_build_object(
            'hand_number', v_hand_num::integer,
            'user_hcp', v_user_hcp,
            'expected_hcp', v_exp_hcp,
            'hcp_ok', v_hcp_ok,
            'user_dist', v_user_dist,
            'expected_dist', v_exp_dist,
            'dist_ok', v_dist_ok,
            'calculated_tcp', coalesce(v_user_hcp, 0) + coalesce(v_user_dist, 0),
            'expected_tcp', v_exp_tcp,
            'user_bid', v_user_bid,
            'expected_bid', v_exp_bid,
            'bid_ok', v_bid_ok,
            'missed_skills', v_missed,
            'explanation', trim(v_diag)
        ));
    END LOOP;

    v_score_pct := CASE WHEN v_total_components > 0 THEN round((v_earned_components::numeric / v_total_components::numeric) * 100)::integer ELSE 0 END;
    v_passed := (v_score_pct >= v_threshold);

    IF v_passed THEN
        v_next_code := CASE p_lesson_code WHEN '1E' THEN '1F' WHEN '1F' THEN '1G' ELSE NULL END;
        IF v_next_code IS NOT NULL THEN
            SELECT l.code, l.is_draft, l.validation_status, l.hands_json
              INTO v_next_lesson
              FROM public.lessons l
             WHERE l.code = v_next_code;

            IF FOUND AND NOT v_next_lesson.is_draft AND v_next_lesson.validation_status = 'validated' AND jsonb_array_length(v_next_lesson.hands_json) > 0 THEN
                IF NOT EXISTS (
                    SELECT 1 FROM public.lesson_assignments la2
                     WHERE la2.member_id = v_member_id AND la2.lesson_code = v_next_code
                ) THEN
                    INSERT INTO public.lesson_assignments (member_id, lesson_code, status, released_at)
                    VALUES (v_member_id, v_next_code, 'Not started', now())
                    ON CONFLICT (member_id, lesson_code) DO NOTHING;
                    v_unlocked_next := v_next_code;
                    INSERT INTO public.member_notifications (member_id, kind, title, body)
                    VALUES (
                        v_member_id,
                        'unlock',
                        format('Lesson %s Unlocked Automatically!', v_next_code),
                        format('You scored %s%% (%s/%s) on Lesson %s, meeting the %s%% threshold.', v_score_pct, v_earned_components, v_total_components, p_lesson_code, v_threshold)
                    );
                END IF;
                v_next_status_note := format('Congratulations! You scored %s%% (%s/%s components >= %s%% threshold). Lesson %s is unlocked and ready!', v_score_pct, v_earned_components, v_total_components, v_threshold, v_next_code);
            ELSE
                v_next_status_note := format('You mastered Lesson %s (%s%% >= %s%%)! Next lesson %s is currently locked awaiting source validation of flagged exercises.', p_lesson_code, v_score_pct, v_threshold, v_next_code);
            END IF;
        END IF;
    ELSE
        v_next_status_note := format('You scored %s%% (%s/%s components). Review the diagnostic explanations below, practise missed hands in "Practice Again", and retry to reach %s%% and unlock the next lesson.', v_score_pct, v_earned_components, v_total_components, v_threshold);
    END IF;

    v_grading_payload := jsonb_build_object(
        'answer_key_version', v_key_ver,
        'graded_at', now(),
        'earned_components', v_earned_components,
        'total_components', v_total_components,
        'denominator_explanation', format('%s hands × 3 scored skills (HCP, Distribution Points, Bid) = %s components. Calculated TCP and optional reasoning/questions are never counted as wrong answers.', v_hand_count, v_total_components),
        'score_pct', v_score_pct,
        'progression_threshold_pct', v_threshold,
        'passed', v_passed,
        'unlocked_next_lesson', v_unlocked_next,
        'next_action_summary', v_next_status_note,
        'skill_breakdown', jsonb_build_object(
            'honour_counting_pct', CASE WHEN v_hand_count > 0 THEN round((v_hcp_correct::numeric / v_hand_count::numeric) * 100)::integer ELSE 0 END,
            'distribution_pct', CASE WHEN v_hand_count > 0 THEN round((v_dist_correct::numeric / v_hand_count::numeric) * 100)::integer ELSE 0 END,
            'fit_recognition_pct', CASE WHEN v_hand_count > 0 THEN round((v_dist_correct::numeric / v_hand_count::numeric) * 100)::integer ELSE 0 END,
            'response_selection_pct', CASE WHEN v_hand_count > 0 THEN round((v_bid_correct::numeric / v_hand_count::numeric) * 100)::integer ELSE 0 END
        ),
        'hands_breakdown', v_breakdown
    );

    v_final_sub_status := CASE WHEN v_has_q THEN 'submitted' ELSE 'reviewed' END;

    -- Save immutable versioned submission under the assignment FOR UPDATE lock
    SELECT s.id, s.version_number
      INTO v_sub_id, v_ver
      FROM public.submissions s
     WHERE s.assignment_id = v_assignment.id
       AND s.member_id = v_member_id
       AND s.status = 'draft'
     ORDER BY s.version_number DESC
     LIMIT 1;

    IF v_sub_id IS NOT NULL THEN
        UPDATE public.submissions
           SET answers_json = coalesce(p_answers_json, '{}'::jsonb),
               learner_questions = v_clean_q,
               client_request_id = v_clean_req_id,
               grading_json = v_grading_payload,
               status = v_final_sub_status,
               submitted_at = now(),
               reviewed_at = CASE WHEN v_has_q THEN NULL ELSE now() END,
               updated_at = now()
         WHERE id = v_sub_id;
    ELSE
        SELECT coalesce(max(s.version_number), 0) + 1
          INTO v_ver
          FROM public.submissions s
         WHERE s.assignment_id = v_assignment.id;

        INSERT INTO public.submissions (
            assignment_id, member_id, lesson_code, version_number, status,
            client_request_id, answers_json, learner_questions, grading_json, submitted_at, reviewed_at
        ) VALUES (
            v_assignment.id, v_member_id, p_lesson_code, v_ver, v_final_sub_status,
            v_clean_req_id, coalesce(p_answers_json, '{}'::jsonb), v_clean_q,
            v_grading_payload, now(), CASE WHEN v_has_q THEN NULL ELSE now() END
        )
        RETURNING id INTO v_sub_id;
    END IF;

    UPDATE public.lesson_assignments
       SET status = CASE
               WHEN v_has_q THEN 'Needs help'
               WHEN v_passed THEN 'Finished'
               ELSE 'Working on it'
           END,
           finished_at = CASE WHEN v_passed THEN coalesce(finished_at, CURRENT_DATE) ELSE finished_at END,
           updated_at = now()
     WHERE id = v_assignment.id;

    UPDATE public.members
       SET interest_status = CASE
               WHEN interest_status IN ('Not contacted', 'Awaiting reply') THEN 'Interested'
               ELSE interest_status
           END,
           updated_at = now()
     WHERE id = v_member_id;

    RETURN jsonb_build_object(
        'submission_id', v_sub_id,
        'version_number', v_ver,
        'status', v_final_sub_status,
        'client_request_id', v_clean_req_id,
        'deduplicated', false,
        'grading', v_grading_payload
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_submit_and_grade_lesson(text, text, jsonb, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_submit_and_grade_lesson(text, text, jsonb, text, text) TO anon, authenticated;

-- -----------------------------------------------------------------------------
-- 5. PRACTICE HAND CHECK WITH LESSON ASSIGNMENT & VALIDATION GATE (FIX #1)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.learner_check_practice_hand(
    p_raw_token text,
    p_lesson_code text,
    p_hand_number integer,
    p_user_ans jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_assignment RECORD;
    v_lesson RECORD;
    v_all_keys jsonb;
    v_item jsonb;
    v_exp_hcp integer;
    v_exp_dist integer;
    v_exp_tcp integer;
    v_exp_bid text;
    v_user_hcp integer;
    v_user_dist integer;
    v_user_bid text;
    v_hcp_ok boolean;
    v_dist_ok boolean;
    v_bid_ok boolean;
    v_diag text := '';
    v_missed jsonb := '[]'::jsonb;
BEGIN
    v_member_id := public.resolve_learner_identity(p_raw_token);

    -- FIX #1A: Enforce that this lesson is assigned/unlocked for the learner
    SELECT la.id, la.status
      INTO v_assignment
      FROM public.lesson_assignments la
     WHERE la.member_id = v_member_id
       AND la.lesson_code = p_lesson_code
     LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_ASSIGNED: Lesson % has not been unlocked for your account.', p_lesson_code
            USING ERRCODE = '42501';
    END IF;

    IF v_assignment.status = 'Paused' THEN
        RAISE EXCEPTION 'ASSIGNMENT_PAUSED: Lesson % is currently paused.', p_lesson_code
            USING ERRCODE = '42501';
    END IF;

    -- FIX #1B: Enforce that the target lesson is published (is_draft = false) and validated
    SELECT l.code, l.is_draft, l.validation_status
      INTO v_lesson
      FROM public.lessons l
     WHERE l.code = p_lesson_code
     LIMIT 1;

    IF NOT FOUND OR v_lesson.is_draft IS TRUE OR v_lesson.validation_status <> 'validated' THEN
        RAISE EXCEPTION 'LESSON_NOT_VALIDATED: Lesson % is locked or unvalidated and cannot be practised.', p_lesson_code
            USING ERRCODE = '22023';
    END IF;

    SELECT coalesce(lpm.answer_key_json, '[]'::jsonb) || coalesce(lpm.extra_answer_key_json, '[]'::jsonb)
      INTO v_all_keys
      FROM public.lesson_private_materials lpm
     WHERE lpm.lesson_code = p_lesson_code;

    IF v_all_keys IS NULL THEN
        RAISE EXCEPTION 'NOT_FOUND: Practice lesson % not found.', p_lesson_code
            USING ERRCODE = 'P0002';
    END IF;

    SELECT elem INTO v_item
      FROM jsonb_array_elements(v_all_keys) elem
     WHERE (elem->>'hand_number')::integer = p_hand_number
     LIMIT 1;

    IF v_item IS NULL THEN
        RAISE EXCEPTION 'NOT_FOUND: Hand % in Lesson % is not in the validated practice bank.', p_hand_number, p_lesson_code
            USING ERRCODE = 'P0002';
    END IF;

    v_exp_hcp := (v_item->>'hcp')::integer;
    v_exp_dist := (v_item->>'dist_pts')::integer;
    v_exp_tcp := (v_item->>'tcp')::integer;
    v_exp_bid := (v_item->>'recommended_bid');

    BEGIN
        v_user_hcp := nullif(regexp_replace(coalesce(p_user_ans->>'hcp', ''), '[^0-9-]', '', 'g'), '')::integer;
    EXCEPTION WHEN OTHERS THEN
        v_user_hcp := NULL;
    END;
    BEGIN
        v_user_dist := nullif(regexp_replace(coalesce(p_user_ans->>'dist_pts', '0'), '[^0-9-]', '', 'g'), '')::integer;
    EXCEPTION WHEN OTHERS THEN
        v_user_dist := NULL;
    END;

    v_user_bid := trim(coalesce(p_user_ans->>'bid', ''));
    IF upper(v_user_bid) IN ('P', 'PASS') THEN v_user_bid := 'Pass'; END IF;
    v_user_bid := replace(replace(replace(replace(upper(v_user_bid), 'PASS', 'Pass'), 'S', '♠'), 'H', '♥'), 'D', '♦');
    v_user_bid := replace(v_user_bid, 'C', '♣');

    v_hcp_ok := (v_user_hcp IS NOT NULL AND v_user_hcp = v_exp_hcp);
    v_dist_ok := (v_user_dist IS NOT NULL AND v_user_dist = v_exp_dist);
    v_bid_ok := (v_user_bid = v_exp_bid);

    IF NOT v_hcp_ok THEN
        v_missed := v_missed || '["honour_counting"]'::jsonb;
        v_diag := v_diag || format('Expected %s HCP (A=4, K=3, Q=2, J=1), you entered %s. ', v_exp_hcp, coalesce(v_user_hcp::text, 'blank'));
    END IF;

    IF NOT v_dist_ok THEN
        v_missed := v_missed || '["distribution", "fit_recognition"]'::jsonb;
        v_diag := v_diag || format('Expected %s distribution points, you entered %s. ', v_exp_dist, coalesce(v_user_dist::text, 'blank'));
    END IF;

    IF NOT v_bid_ok THEN
        v_missed := v_missed || '["response_selection"]'::jsonb;
        v_diag := v_diag || format('Expected bid %s (%s), you selected %s.', v_exp_bid, coalesce(v_item->>'notes', ''), coalesce(nullif(v_user_bid, ''), 'blank'));
    END IF;

    IF v_hcp_ok AND v_dist_ok AND v_bid_ok THEN
        v_diag := format('Spot on! %s HCP + %s Dist = %s TCP -> %s. %s', v_exp_hcp, v_exp_dist, v_exp_tcp, v_exp_bid, coalesce(v_item->>'notes', ''));
        UPDATE public.learner_mistake_queue
           SET mastered = true,
               last_diagnostic = v_diag,
               updated_at = now()
         WHERE member_id = v_member_id
           AND lesson_code = p_lesson_code
           AND hand_number = p_hand_number;
    ELSE
        INSERT INTO public.learner_mistake_queue (
            member_id, lesson_code, hand_number, missed_skills, last_diagnostic, times_missed, mastered, updated_at
        ) VALUES (
            v_member_id, p_lesson_code, p_hand_number, v_missed, trim(v_diag), 1, false, now()
        )
        ON CONFLICT (member_id, lesson_code, hand_number) DO UPDATE
           SET mastered = false,
               missed_skills = EXCLUDED.missed_skills,
               last_diagnostic = EXCLUDED.last_diagnostic,
               times_missed = public.learner_mistake_queue.times_missed + 1,
               updated_at = now();
    END IF;

    RETURN jsonb_build_object(
        'hand_number', p_hand_number,
        'user_hcp', v_user_hcp,
        'expected_hcp', v_exp_hcp,
        'hcp_ok', v_hcp_ok,
        'user_dist', v_user_dist,
        'expected_dist', v_exp_dist,
        'dist_ok', v_dist_ok,
        'calculated_tcp', coalesce(v_user_hcp, 0) + coalesce(v_user_dist, 0),
        'expected_tcp', v_exp_tcp,
        'user_bid', v_user_bid,
        'expected_bid', v_exp_bid,
        'bid_ok', v_bid_ok,
        'missed_skills', v_missed,
        'explanation', trim(v_diag)
    );
END;
$$;

REVOKE ALL ON FUNCTION public.learner_check_practice_hand(text, text, integer, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_check_practice_hand(text, text, integer, jsonb) TO anon, authenticated;

-- -----------------------------------------------------------------------------
-- 6. ATOMIC, RETRY-SAFE SESSION JOIN / LEAVE (`public.learner_manage_session`, FIX #2)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.learner_manage_session(
    p_raw_token text,
    p_action text,
    p_session_id uuid DEFAULT NULL,
    p_title text DEFAULT '',
    p_scheduled_pkt text DEFAULT '',
    p_focus_topic text DEFAULT '',
    p_external_bbo_note text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_clean_title text;
    v_clean_pkt text;
    v_clean_focus text;
    v_clean_note text;
    v_sess RECORD;
    v_cur_count integer;
    v_new_id uuid;
BEGIN
    v_member_id := public.resolve_learner_identity(p_raw_token);

    IF p_action = 'create' THEN
        v_clean_title := public.sanitize_club_text(p_title);
        v_clean_pkt := public.sanitize_club_text(p_scheduled_pkt);
        v_clean_focus := coalesce(nullif(public.sanitize_club_text(p_focus_topic), ''), 'Lesson 1E & 1F Practice');
        v_clean_note := coalesce(nullif(public.sanitize_club_text(p_external_bbo_note), ''), 'Lahore Bridge Club In-App Table & Voice Room');

        IF char_length(v_clean_title) = 0 OR char_length(v_clean_pkt) = 0 THEN
            RAISE EXCEPTION 'VALIDATION_ERROR: Session title and PKT schedule time are required.'
                USING ERRCODE = '22023';
        END IF;

        INSERT INTO public.practice_sessions (
            host_id, title, scheduled_pkt, focus_topic, external_bbo_note, max_players
        ) VALUES (
            v_member_id, v_clean_title, v_clean_pkt, v_clean_focus, v_clean_note, 4
        )
        RETURNING id INTO v_new_id;

        INSERT INTO public.practice_session_rsvps (session_id, member_id)
        VALUES (v_new_id, v_member_id)
        ON CONFLICT (session_id, member_id) DO NOTHING;

        RETURN jsonb_build_object(
            'status', 'created',
            'session_id', v_new_id,
            'seated_count', 1,
            'max_players', 4
        );

    ELSIF p_action = 'join' THEN
        -- Row-level lock on practice_sessions serializes concurrent joiners
        SELECT ps.id, ps.max_players
          INTO v_sess
          FROM public.practice_sessions ps
         WHERE ps.id = p_session_id
           FOR UPDATE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'NOT_FOUND: Practice session not found.'
                USING ERRCODE = 'P0002';
        END IF;

        -- Idempotent retry check: if already seated, do not fail or double-seat
        IF EXISTS (
            SELECT 1 FROM public.practice_session_rsvps r
             WHERE r.session_id = p_session_id AND r.member_id = v_member_id
        ) THEN
            SELECT count(*)::integer INTO v_cur_count
              FROM public.practice_session_rsvps r
             WHERE r.session_id = p_session_id;

            RETURN jsonb_build_object(
                'status', 'joined',
                'idempotent', true,
                'session_id', p_session_id,
                'seated_count', v_cur_count,
                'max_players', v_sess.max_players
            );
        END IF;

        SELECT count(*)::integer INTO v_cur_count
          FROM public.practice_session_rsvps r
         WHERE r.session_id = p_session_id;

        IF v_cur_count >= v_sess.max_players THEN
            RAISE EXCEPTION 'SESSION_FULL: This practice table is already full (%/% players seated).', v_cur_count, v_sess.max_players
                USING ERRCODE = '22023';
        END IF;

        INSERT INTO public.practice_session_rsvps (session_id, member_id)
        VALUES (p_session_id, v_member_id)
        ON CONFLICT (session_id, member_id) DO NOTHING;

        RETURN jsonb_build_object(
            'status', 'joined',
            'idempotent', false,
            'session_id', p_session_id,
            'seated_count', v_cur_count + 1,
            'max_players', v_sess.max_players
        );

    ELSIF p_action = 'leave' THEN
        SELECT ps.id, ps.max_players
          INTO v_sess
          FROM public.practice_sessions ps
         WHERE ps.id = p_session_id
           FOR UPDATE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'NOT_FOUND: Practice session not found.'
                USING ERRCODE = 'P0002';
        END IF;

        DELETE FROM public.practice_session_rsvps
         WHERE session_id = p_session_id AND member_id = v_member_id;

        SELECT count(*)::integer INTO v_cur_count
          FROM public.practice_session_rsvps r
         WHERE r.session_id = p_session_id;

        RETURN jsonb_build_object(
            'status', 'left',
            'idempotent', true,
            'session_id', p_session_id,
            'seated_count', v_cur_count,
            'max_players', v_sess.max_players
        );

    ELSE
        RAISE EXCEPTION 'VALIDATION_ERROR: Invalid session action %. Use create, join, or leave.', p_action
            USING ERRCODE = '22023';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.learner_manage_session(text, text, uuid, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_manage_session(text, text, uuid, text, text, text, text) TO anon, authenticated;

-- -----------------------------------------------------------------------------
-- 7. FRIENDS-ONLY DIRECT MESSAGING & STUDY GROUP RPCS
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

CREATE OR REPLACE FUNCTION public.learner_manage_study_group(
    p_raw_token text,
    p_action text,
    p_group_id uuid DEFAULT NULL,
    p_name text DEFAULT '',
    p_focus_lesson text DEFAULT '1E',
    p_description text DEFAULT '',
    p_meeting_time_pkt text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
    v_member_id uuid;
    v_clean_name text;
    v_clean_desc text;
    v_clean_time text;
    v_focus text;
    v_new_id uuid;
BEGIN
    v_member_id := public.resolve_learner_identity(p_raw_token);

    IF p_action = 'create' THEN
        v_clean_name := public.sanitize_club_text(p_name);
        v_clean_desc := public.sanitize_club_text(p_description);
        v_clean_time := public.sanitize_club_text(p_meeting_time_pkt);
        v_focus := CASE WHEN p_focus_lesson IN ('1E', '1F', '1G') THEN p_focus_lesson ELSE '1E' END;

        IF char_length(v_clean_name) = 0 THEN
            RAISE EXCEPTION 'VALIDATION_ERROR: Study group name is required.'
                USING ERRCODE = '22023';
        END IF;

        INSERT INTO public.study_groups (
            creator_id, name, focus_lesson, description, meeting_time_pkt
        ) VALUES (
            v_member_id, v_clean_name, v_focus, v_clean_desc, v_clean_time
        )
        RETURNING id INTO v_new_id;

        INSERT INTO public.study_group_members (group_id, member_id)
        VALUES (v_new_id, v_member_id)
        ON CONFLICT (group_id, member_id) DO NOTHING;

        RETURN jsonb_build_object('status', 'created', 'group_id', v_new_id);

    ELSIF p_action = 'join' THEN
        IF NOT EXISTS (SELECT 1 FROM public.study_groups WHERE id = p_group_id) THEN
            RAISE EXCEPTION 'NOT_FOUND: Study group not found.'
                USING ERRCODE = 'P0002';
        END IF;

        INSERT INTO public.study_group_members (group_id, member_id)
        VALUES (p_group_id, v_member_id)
        ON CONFLICT (group_id, member_id) DO NOTHING;

        RETURN jsonb_build_object('status', 'joined', 'group_id', p_group_id);

    ELSIF p_action = 'leave' THEN
        DELETE FROM public.study_group_members
         WHERE group_id = p_group_id AND member_id = v_member_id;

        RETURN jsonb_build_object('status', 'left', 'group_id', p_group_id);
    ELSE
        RAISE EXCEPTION 'VALIDATION_ERROR: Invalid study group action %. Use create, join, or leave.', p_action
            USING ERRCODE = '22023';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.learner_manage_study_group(text, text, uuid, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.learner_manage_study_group(text, text, uuid, text, text, text, text) TO anon, authenticated;

-- -----------------------------------------------------------------------------
-- 8. UPGRADED ORGANISER DASHBOARD, REPORTED DM MODERATION & FOUNDING 100 CONFIG
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.organiser_get_dashboard()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_club_settings jsonb;
    v_lessons jsonb;
    v_members jsonb;
    v_reported_posts jsonb;
    v_reported_dms jsonb;
    v_mistake_queue jsonb;
    v_founders_count integer;
BEGIN
    v_uid := public.assert_is_organiser();

    SELECT count(*)::integer INTO v_founders_count
      FROM public.members
     WHERE founder_number IS NOT NULL;

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

    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
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
            'validation_status', l.validation_status,
            'private_materials', jsonb_build_object(
                'answer_key_json', coalesce(lpm.answer_key_json, '[]'::jsonb),
                'extra_answer_key_json', coalesce(lpm.extra_answer_key_json, '[]'::jsonb),
                'organiser_source_notes', coalesce(lpm.organiser_source_notes, '')
            )
        ) ORDER BY l.seq_order ASC
    ), '[]'::jsonb)
    INTO v_lessons
    FROM public.lessons l
    LEFT JOIN public.lesson_private_materials lpm ON lpm.lesson_code = l.code;

    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', m.id,
            'name', m.name,
            'email', m.email,
            'interest_status', m.interest_status,
            'availability_pkt', m.availability_pkt,
            'experience', m.experience,
            'auth_linked', (m.auth_user_id IS NOT NULL),
            'email_verified', (m.email_verified_at IS NOT NULL),
            'membership_tier', m.membership_tier,
            'founder_number', m.founder_number,
            'founder_granted_at', m.founder_granted_at,
            'last_emailed_date', m.last_emailed_date,
            'follow_up_date', m.follow_up_date,
            'follow_up_check', CASE
                WHEN m.interest_status = 'Not interested' THEN 'Closed'
                WHEN m.follow_up_date IS NULL THEN ''
                WHEN m.follow_up_date <= CURRENT_DATE THEN 'Due'
                ELSE 'Scheduled'
            END,
            'organiser_notes', coalesce(mpn.organiser_notes, ''),
            'questions_next_action', coalesce(mpn.questions_next_action, ''),
            'active_invitation', (
                SELECT jsonb_build_object(
                    'id', li.id,
                    'token_prefix', li.token_prefix,
                    'created_at', li.created_at,
                    'expires_at', li.expires_at,
                    'revoked_at', li.revoked_at,
                    'last_used_at', li.last_used_at,
                    'is_active', (li.revoked_at IS NULL AND li.expires_at > now())
                )
                FROM public.learner_invitations li
                WHERE li.member_id = m.id
                ORDER BY li.created_at DESC
                LIMIT 1
            ),
            'assignments', coalesce((
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'id', la.id,
                        'lesson_code', la.lesson_code,
                        'status', la.status,
                        'released_at', la.released_at,
                        'finished_at', la.finished_at,
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
                        ), '[]'::jsonb)
                    ) ORDER BY (
                        CASE la.lesson_code WHEN '1E' THEN 1 WHEN '1F' THEN 2 WHEN '1G' THEN 3 ELSE 9 END
                    ) ASC
                )
                FROM public.lesson_assignments la
                WHERE la.member_id = m.id
            ), '[]'::jsonb)
        ) ORDER BY (CASE WHEN m.interest_status = 'Organiser' THEN 0 ELSE 1 END), m.created_at ASC
    ), '[]'::jsonb)
    INTO v_members
    FROM public.members m
    LEFT JOIN public.member_private_notes mpn ON mpn.member_id = m.id;

    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', rp.id,
            'author_id', rp.author_id,
            'author_name', coalesce(am.name, 'Club Member'),
            'category', rp.category,
            'lesson_code', rp.lesson_code,
            'title', rp.title,
            'body', rp.body,
            'moderation_status', rp.moderation_status,
            'report_reason', rp.report_reason,
            'reported_by', rp.reported_by,
            'created_at', rp.created_at
        ) ORDER BY rp.updated_at DESC
    ), '[]'::jsonb)
    INTO v_reported_posts
    FROM public.community_posts rp
    LEFT JOIN public.members am ON am.id = rp.author_id
    WHERE rp.moderation_status = 'reported';

    -- ONLY explicitly reported Direct Messages are visible for moderation; private non-reported DMs are never exposed!
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'id', dm.id,
            'sender_id', dm.sender_id,
            'sender_name', coalesce(sm.name, 'Club Member'),
            'recipient_id', dm.recipient_id,
            'recipient_name', coalesce(rm.name, 'Club Member'),
            'body', dm.body,
            'moderation_status', dm.moderation_status,
            'report_reason', dm.report_reason,
            'reported_by', dm.reported_by,
            'created_at', dm.created_at
        ) ORDER BY dm.updated_at DESC
    ), '[]'::jsonb)
    INTO v_reported_dms
    FROM public.direct_messages dm
    LEFT JOIN public.members sm ON sm.id = dm.sender_id
    LEFT JOIN public.members rm ON rm.id = dm.recipient_id
    WHERE dm.moderation_status = 'reported';

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
        )
    ), '[]'::jsonb)
    INTO v_mistake_queue
    FROM public.learner_mistake_queue mq;

    RETURN jsonb_build_object(
        'organiser_uid', v_uid,
        'club_settings', v_club_settings,
        'lessons', v_lessons,
        'members', v_members,
        'reported_posts', v_reported_posts,
        'reported_direct_messages', v_reported_dms,
        'mistake_queue', v_mistake_queue
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_get_dashboard() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_get_dashboard() TO authenticated;

CREATE OR REPLACE FUNCTION public.organiser_moderate_direct_message(
    p_message_id uuid,
    p_decision text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
    v_new_status text;
BEGIN
    v_uid := public.assert_is_organiser();

    IF p_decision NOT IN ('hide', 'dismiss') THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Moderation decision must be hide or dismiss.'
            USING ERRCODE = '22023';
    END IF;

    v_new_status := CASE WHEN p_decision = 'hide' THEN 'hidden_by_mod' ELSE 'visible' END;

    -- Can only moderate messages that were explicitly reported by a participant
    UPDATE public.direct_messages
       SET moderation_status = v_new_status,
           report_reason = CASE WHEN p_decision = 'dismiss' THEN '' ELSE report_reason END,
           updated_at = now()
     WHERE id = p_message_id
       AND moderation_status = 'reported';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND: Reported direct message not found.'
            USING ERRCODE = 'P0002';
    END IF;

    RETURN jsonb_build_object(
        'status', 'ok',
        'message_id', p_message_id,
        'moderation_status', v_new_status
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_moderate_direct_message(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_moderate_direct_message(uuid, text) TO authenticated;

CREATE OR REPLACE FUNCTION public.organiser_update_club_settings(
    p_threshold_pct integer DEFAULT 80,
    p_founding_100_benefits_json jsonb DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_uid uuid;
BEGIN
    v_uid := public.assert_is_organiser();

    IF p_threshold_pct IS NULL OR p_threshold_pct < 50 OR p_threshold_pct > 100 THEN
        RAISE EXCEPTION 'VALIDATION_ERROR: Progression threshold must be between 50% and 100%.'
            USING ERRCODE = '22023';
    END IF;

    UPDATE public.club_settings
       SET progression_threshold_pct = p_threshold_pct,
           founding_100_benefits_json = coalesce(p_founding_100_benefits_json, founding_100_benefits_json),
           updated_at = now()
     WHERE id = 1;

    RETURN jsonb_build_object(
        'progression_threshold_pct', p_threshold_pct,
        'founding_100_benefits_json', (SELECT founding_100_benefits_json FROM public.club_settings WHERE id = 1)
    );
END;
$$;

REVOKE ALL ON FUNCTION public.organiser_update_club_settings(integer, jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.organiser_update_club_settings(integer, jsonb) TO authenticated;


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

COMMIT;
