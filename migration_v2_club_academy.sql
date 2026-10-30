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