create user orand with password 'orandpassword';

create database orand owner orand template template0;

\c orand

-- public.keyring definition
-- Drop table
-- DROP TABLE public.keyring;

create table public.keyring (
	id bigserial not null,
	username varchar not null,
	hmac_secret varchar not null,
	public_key varchar not null,
	secret_key varchar not null,
	created_date timestamp not null default CURRENT_TIMESTAMP,
	constraint index_username unique (username),
	constraint keyring_pkey primary key (id),
	constraint keyring_public_key_key unique (public_key),
	constraint keyring_secret_key_key unique (secret_key)
);

ALTER TABLE public.keyring OWNER TO orand;

-- public.receiver definition
-- Drop table
-- DROP TABLE public.receiver;

create table public.receiver (
	id bigserial not null,
	"name" varchar not null,
	address varchar not null,
	network int8 not null,
	nonce int8 not null,
	created_date timestamp not null default CURRENT_TIMESTAMP,
	constraint index_name unique (name),
	constraint receiver_pkey primary key (id)
);

ALTER TABLE public.receiver ADD keyring_id bigint NULL;
ALTER TABLE public.receiver ADD CONSTRAINT receiver_keyring_foreign FOREIGN KEY (id) REFERENCES public.keyring(id);
CREATE INDEX receiver_keyring_id_idx ON public.receiver (keyring_id);

ALTER TABLE public.receiver OWNER TO orand;

-- public.randomness definition
-- Drop table
-- DROP TABLE public.randomness;

create table public.randomness (
	id bigserial not null,
	keyring_id int8 not null,
	receiver_id int8 not null,
	epoch int8 not null,
	alpha varchar not null,
	gamma varchar not null,
	c varchar not null,
	s varchar not null,
	y varchar not null,
	witness_address varchar not null,
	witness_gamma varchar not null,
	witness_hash varchar not null,
	inverse_z varchar not null,
	signature_proof varchar not null,
	created_date timestamp not null default CURRENT_TIMESTAMP,
	constraint index_alpha unique (alpha),
	constraint index_y unique (y),
	constraint randomness_pkey primary key (id),
	constraint randomness_signature_proof_key unique (signature_proof),
	constraint link_randomness_to_keyring foreign key (keyring_id) references public.keyring(id),
	constraint link_randomness_to_receiver foreign key (receiver_id) references public.receiver(id)
);

ALTER TABLE public.randomness OWNER TO orand;
