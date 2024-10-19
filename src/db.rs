use rusqlite::Connection;
use std::sync::Mutex;

pub type DbConnection = Mutex<Connection>;

//type DbConnection = Mutex<Connection>;

pub fn init_db() -> DbConnection {
    let conn = Connection::open("todo.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )",
        [],
    )
    .unwrap();

    conn.execute(
        "CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            due_date TEXT NOT NULL,
            status TEXT NOT NULL,
            assignee TEXT NOT NULL,
            FOREIGN KEY (assignee) REFERENCES users(username)
        )",
        [],
    )
    .unwrap();

    //  conn
    Mutex::new(conn) // Wrap the Connection in a Mutex and return
}
