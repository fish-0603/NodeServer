-- SmartGuide 資料庫完整結構
-- 從目前正在使用的 App 資料庫 dump 出來，包含兩個 migrations 的異動
--
-- 下載這個 repo 的人可以這樣建立一模一樣的資料庫：
--
--   1. 用 psql 或 pgAdmin 建立一個空的資料庫，名稱建議跟 .env 的 DB_NAME 一致（預設 App）
--        createdb -U postgres App
--   2. 對這個空資料庫執行這份檔案
--        psql -U postgres -d App -f database_schema.sql
--
-- 之後有新的欄位異動，請在 migrations/ 資料夾新增一支新的 SQL 檔案，
-- 不要直接改這份檔案（這份是「初始建置用」，不是持續維護的 migration）。

CREATE TABLE public.alert_logs (
    id integer NOT NULL,
    alert_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    alert_text text,
    source_type character varying(20),
    gps_location text
);

CREATE SEQUENCE public.alert_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.alert_logs_id_seq OWNED BY public.alert_logs.id;

CREATE TABLE public.connections (
    id integer NOT NULL,
    blind_id integer,
    caregiver_id integer,
    status character varying(20) DEFAULT 'pending'::character varying,
    requester_id integer,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    is_emergency boolean DEFAULT false
);

CREATE SEQUENCE public.connections_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.connections_id_seq OWNED BY public.connections.id;

CREATE TABLE public.hardware_logs (
    id integer NOT NULL,
    log_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    distance double precision,
    tilt_angle double precision
);

CREATE SEQUENCE public.hardware_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.hardware_logs_id_seq OWNED BY public.hardware_logs.id;

CREATE TABLE public.sos_events (
    id integer NOT NULL,
    user_id integer,
    event_type character varying(50),
    latitude double precision,
    longitude double precision,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

CREATE SEQUENCE public.sos_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.sos_events_id_seq OWNED BY public.sos_events.id;

CREATE TABLE public.users (
    user_id integer NOT NULL,
    full_name character varying(20) NOT NULL,
    username character varying(20) NOT NULL,
    password_hash text,
    phone character varying(15) NOT NULL,
    email text,
    fcm_token text,
    role character varying(20) DEFAULT 'blind'::character varying,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    google_id character varying(255),
    auth_provider character varying(20) DEFAULT 'local'::character varying NOT NULL,
    CONSTRAINT check_phone_format CHECK (((phone)::text ~ '^09[0-9]{8}$'::text))
);

CREATE SEQUENCE public.users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;

CREATE TABLE public.vision_logs (
    id integer NOT NULL,
    obs_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    obstacle_type character varying(50),
    distance_cm double precision,
    gps_location text
);

CREATE SEQUENCE public.vision_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.vision_logs_id_seq OWNED BY public.vision_logs.id;

ALTER TABLE ONLY public.alert_logs ALTER COLUMN id SET DEFAULT nextval('public.alert_logs_id_seq'::regclass);
ALTER TABLE ONLY public.connections ALTER COLUMN id SET DEFAULT nextval('public.connections_id_seq'::regclass);
ALTER TABLE ONLY public.hardware_logs ALTER COLUMN id SET DEFAULT nextval('public.hardware_logs_id_seq'::regclass);
ALTER TABLE ONLY public.sos_events ALTER COLUMN id SET DEFAULT nextval('public.sos_events_id_seq'::regclass);
ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);
ALTER TABLE ONLY public.vision_logs ALTER COLUMN id SET DEFAULT nextval('public.vision_logs_id_seq'::regclass);

ALTER TABLE ONLY public.alert_logs
    ADD CONSTRAINT alert_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_blind_id_caregiver_id_key UNIQUE (blind_id, caregiver_id);

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.hardware_logs
    ADD CONSTRAINT hardware_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sos_events
    ADD CONSTRAINT sos_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_google_id_key UNIQUE (google_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);

ALTER TABLE ONLY public.vision_logs
    ADD CONSTRAINT vision_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_blind_id_fkey FOREIGN KEY (blind_id) REFERENCES public.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_caregiver_id_fkey FOREIGN KEY (caregiver_id) REFERENCES public.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_requester_id_fkey FOREIGN KEY (requester_id) REFERENCES public.users(user_id);

ALTER TABLE ONLY public.sos_events
    ADD CONSTRAINT sos_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;
