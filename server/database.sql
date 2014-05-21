drop table if exists users;
create table users (
    user_id int NOT NULL PRIMARY KEY auto_increment,
    username varchar(64) not null,
    password char(68) not null,
    public_key_fp bigint default 0,
    public_key BLOB default null,
    UNIQUE(username)
);

insert into users (user_id, username, password) VALUES
(1, "laptop1", "laptop1pass"),
(2, "laptop2", "laptop2pass"),
(3, "desktop", "desktoppass"),
(4, "test", "testpass"),
(NULL, "test1", "testpass"),
(NULL, "test2", "testpass"),
(NULL, "test3", "testpass"),
(NULL, "test4", "testpass");

drop table if exists contacts;
create table contacts (
	user_id int not null,
	contact_id int not null,
	unique(user_id, contact_id)
);

insert into contacts VALUES
(1, 2),(1, 3),(1, 4),
(2, 1),(2, 3),(2, 4),
(3, 1),(3, 2),(3, 4),
(4, 1),(4, 2),(4, 3);

drop table if exists stored_events;
create table stored_events (
	event_id int not null PRIMARY KEY auto_increment,
	src_contact_id int not null,
	dst_contact_id int not null,
	type enum('message', 'call') not null,
	data_id int default null, 
	data BLOB default null
);

