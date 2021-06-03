mod access_control;

extern crate argon2;
extern crate csv;
extern crate passablewords;
use crate::access_control::{is_allowed, CONFIG, POLICY};
use crate::Actions::StudentAction;
use argon2::{Config, ThreadMode, Variant, Version};
use futures::executor::block_on;
use lazy_static::{__Deref, lazy_static};
use passablewords::{check_password, PasswordError};
use rand::rngs::OsRng;
use rand::RngCore;
use read_input::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::Mutex;

// TODO:
// all functions take users as parameter
// all warn! will trough errors : quentin
// logs : gaetan
// input validation username only alphanum max 20 chars : quentin

const DATABASE_FILE: &str = "db.txt";

const ADMIN: &str = "admin";
const TEACHER: &str = "teacher";
const STUDENT: &str = "student";

const ADMIN_ACTION: &str = "admin_action";
const TEACHER_ACTION: &str = "teacher_action";
const STUDENT_ACTION: &str = "student_action";

lazy_static! {
    static ref DATABASE: Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>> = {
        let map = read_database_from_file(DATABASE_FILE).unwrap_or(HashMap::new());

        Mutex::new(map)
    };
}

pub enum KingError {
    AccessDenied,
    LoginFailed,
    AlreadyRegistered,
}

enum Actions {
    AdminAction,
    TeacherAction,
    StudentAction,
}

fn read_database_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<HashMap<String, (Vec<u8>, Vec<u8>)>, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let map = serde_json::from_reader(reader)?;
    Ok(map)
}
fn check_username(username: &str) -> bool {
    let re = Regex::new(r"^[\da-z]{1,20}$").unwrap();
    re.is_match(username)
}
fn check_pass(password: &String) -> bool {
    let good;
    match check_password(password.as_str()) {
        Ok(..) => {
            good = true;
        }
        Err(err) => {
            match err {
                PasswordError::TooShort => {
                    println!("Your password should be longer than 8 characters")
                }
                PasswordError::TooCommon => println!("Your should be more unique"),
                PasswordError::TooSimple => println!("Your should be more random"),
                PasswordError::InternalError => println!("Internal error"),
                _ => {}
            }
            good = false;
        }
    }
    good
}
//tmp function
fn register(username: &str, salt: &Vec<u8>, password: &Vec<u8>) {
    let password = password.clone();
    let salt = salt.clone();
    let mut map = DATABASE.lock().unwrap();
    map.insert(String::from(username), (salt, password));
}

fn register_user(role: &str) {
    let username: String = input()
        .msg("Please input username: ")
        .add_test(|x: &String| check_username(x.as_str()))
        .get();
    let password: String = input().msg("Please input password: ").get();

    if !already_registered(username.as_str()) {
        // write role access rights into csv policy file
        let mut policy_file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(POLICY)
            .unwrap();
        let mut wtr = csv::Writer::from_writer(policy_file);
        wtr.write_record(&["g", username.as_str(), role]);

        // save credentials in hashmap
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let hashed_password = hash_password(password.as_str(), salt, 1);
        let mut map = DATABASE.lock().unwrap();
        map.insert(
            String::from(username.as_str()),
            (Vec::from(salt), hashed_password),
        );
        println!("register success");
    } else {
        println!("User already registered.");
    }
}

fn already_registered(user: &str) -> bool {
    let mut map = DATABASE.lock().unwrap();
    let data = map.get_mut(&String::from(user));
    return match data {
        Some(_) => true,
        None => false,
    };
}

fn is_correct_password(to_check: &Vec<u8>, password: &Vec<u8>) -> bool {
    let mut is_same = true;
    for i in 0..password.len() {
        if to_check[i] != password[i] {
            is_same = false;
        }
    }
    is_same
}

// TODO: Logging in this function, return name of user inside Result, bruteforce protection : quentin
fn welcome() -> Result<String, KingError> {
    let mut incremental_timer = 1;
    while true {
        let username: String = input()
            .msg("Please input username: or break ")
            .add_test(|x: &String| check_username(x.as_str()))
            .get();
        if username.as_str() == "break" {
            return Err(KingError::LoginFailed);
        }

        let password: String = input().msg("Please input password: ").get();
        let mut map = DATABASE.lock().unwrap();
        let data = map.get_mut(&username);
        match data {
            Some(v) => {
                let salt = v.0.clone();
                let hashed_password = hash_password(
                    password.as_str(),
                    <[u8; 16]>::try_from(salt).unwrap(),
                    incremental_timer,
                );
                if is_correct_password(&hashed_password, &v.1) {
                    println!("login succes");
                    return Ok(username);
                } else {
                    incremental_timer *= 2;
                }
            }
            None => {
                drop(map);

                let mut salt = [0u8; 16];
                OsRng.fill_bytes(&mut salt);
                let hashed_password = hash_password(password.as_str(), salt, incremental_timer);
                register(username.as_str(), &Vec::from(salt), &hashed_password);
                println!("register success");
                return Ok(username);
            }
        };
    }
    Err(KingError::LoginFailed)
}

fn menu(user: &str) {
    println!("*****\n1: Student menu\n2: Teacher menu\n3: Admin menu\n4 About\n0: Quit");
    let choice = input().inside(0..=3).msg("Enter Your choice: ").get();
    match choice {
        1 => student_action(user),
        2 => teacher_action(user),
        3 => admin_action(user),
        4 => about(),
        0 => quit(),
        _ => panic!("impossible choice"),
    }
}

// TODO: admin_actions : gaetan
// become_teacher options
fn admin_action(user: &str) {
    println!("*****\n1: Add teacher\n2: Add student\n3: About\n0: Quit");
    let choice = input().inside(0..=4).msg("Enter Your choice: ").get();
    match choice {
        1 => register_user(ADMIN),
        2 => register_user(STUDENT),
        3 => about(),
        0 => quit(),
        _ => panic!("impossible choice"),
    }
}

fn student_action(user: &str) {
    if block_on(access_control::is_allowed(user, STUDENT_ACTION)) {
        // TODO: log info!
        println!("*****\n1: See your grades\n2: Teachers' menu\n3: About\n0: Quit");
        let choice = input().inside(0..=3).msg("Enter Your choice: ").get();
        match choice {
            1 => show_grades("Enter your name. Do NOT lie!"),
            // TODO: remove this option : quentin
            3 => about(),
            0 => quit(),
            _ => panic!("impossible choice"),
        }
    } else {
        // TODO: log warn!
    }
}

fn teacher_action(user: &str) {
    println!("*****\n1: See grades of student\n2: Enter grades\n3 About\n0: Quit");
    let choice = input().inside(0..=3).msg("Enter Your choice: ").get();
    match choice {
        1 => show_grades("Enter the name of the user of which you want to see the grades:"),
        2 => enter_grade(),
        3 => about(),
        0 => quit(),
        _ => panic!("impossible choice"),
    }
}

// TODO: take message and username as parameter check with cabin if access to grades authorized + logs : quentin
fn show_grades(message: &str) {
    println!("{}", message);
    let name: String = input().get();
    println!("Here are the grades of user {}", name);
    //other file
    //let db = DATABASE.lock().unwrap();

    // match db.get(&name) {
    //     Some(grades) => {
    //         println!("{:?}", grades);
    //         println!(
    //             "The average is {}",
    //             (grades.iter().sum::<f32>()) / ((*grades).len() as f32)
    //         );
    //     }
    //     None => println!("User not in system"),
    // };
}

// TODO: function called by admin_action => change access rights of username with casbin : gaetan
// fn become_teacher() {
//     println!("Are you a prof? (yes/no) Do NOT lie!");
//     let rep: String = input().get();
//     if rep == "yes" {
//         println!("Access allowed");
//         *teacher = true;
//     } else {
//         println!("Access denied");
//     }
// }

// TODO: if students not exist error : quentin
fn enter_grade() {
    println!("What is the name of the student?");
    let name: String = input().get();
    println!("What is the new grade of the student?");
    let grade: f32 = input().add_test(|x| *x >= 0.0 && *x <= 6.0).get();
    // change file with validation
    // let mut map = DATABASE.lock().unwrap();
    // match map.get_mut(&name) {
    //     Some(v) => v.push(grade),
    //     None => {
    //         map.insert(name, vec![grade]);
    //     }
    // };
}

fn about() {
    panic!("The requested URL was not found on this server.");
}

fn quit() {
    println!("Saving database!");
    let file = File::create(DATABASE_FILE).unwrap();
    let writer = BufWriter::new(file);
    serde_json::to_writer(writer, DATABASE.lock().unwrap().deref()).unwrap();
    std::process::exit(0);
}
fn hash_password(password: &str, salt: [u8; 16], time: u32) -> Vec<u8> {
    let config = Config {
        variant: Variant::Argon2i,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: time,
        lanes: 4,
        thread_mode: ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };
    let hash = argon2::hash_raw(password.as_bytes(), &salt[0..], &config).unwrap();

    hash[0..32].to_vec()
}

fn main() {
    let user = welcome();
    if user.is_ok() {
        let user = user.ok().unwrap();
        loop {
            menu(user.as_str());
        }
    }
}
