use lazy_static::{__Deref, lazy_static};
use read_input::prelude::*;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::Mutex;

// TODO:
// all functions take users as parameter
// all warn! will trough errors : quentin
// logs : gaetan
// input validation username only alphanum max 20 chars : quentin

const DATABASE_FILE: &str = "db.txt";

lazy_static! {
    static ref DATABASE: Mutex<HashMap<String, Vec<f32>>> = {
        let map = read_database_from_file(DATABASE_FILE).unwrap_or(HashMap::new());
        Mutex::new(map)
    };
}

pub enum KingError {
    AccessDenied,
}

fn read_database_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<HashMap<String, Vec<f32>>, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let map = serde_json::from_reader(reader)?;
    Ok(map)
}
// TODO: Logging in this function, return name of user inside Result, bruteforce protection : quentin
fn welcome() {
    println!("Welcome to KING: KING Is Not GAPS");
}

// TODO: username as parameter casbin will check access to function : gaetan
fn menu(teacher: &mut bool) {
    if *teacher {
        teacher_action();
    } else {
        student_action(teacher);
    }
}

// TODO: admin_actions : gaetan
// add remove teacher/student
// become_teacher options

fn student_action(teacher: &mut bool) {
    println!("*****\n1: See your grades\n2: Teachers' menu\n3: About\n0: Quit");
    let choice = input().inside(0..=3).msg("Enter Your choice: ").get();
    match choice {
        1 => show_grades("Enter your name. Do NOT lie!"),
        // TODO: remove this option : quentin
        2 => become_teacher(teacher),
        3 => about(),
        0 => quit(),
        _ => panic!("impossible choice"),
    }
}

fn teacher_action() {
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

// TODO: check with casbin if username authorized: gaetan
fn is_allowed(username: &str, object: &str) -> Result<(), KingError> {
    Ok(())
}

// TODO: take message and username as parameter check with cabin if access to grades authorized + logs : quentin
fn show_grades(message: &str) {
    println!("{}", message);
    let name: String = input().get();
    println!("Here are the grades of user {}", name);
    let db = DATABASE.lock().unwrap();
    match db.get(&name) {
        Some(grades) => {
            println!("{:?}", grades);
            println!(
                "The average is {}",
                (grades.iter().sum::<f32>()) / ((*grades).len() as f32)
            );
        }
        None => println!("User not in system"),
    };
}

// TODO: function called by admin_action => change access rights of username with casbin : gaetan
fn become_teacher(teacher: &mut bool) {
    println!("Are you a prof? (yes/no) Do NOT lie!");
    let rep: String = input().get();
    if rep == "yes" {
        println!("Access allowed");
        *teacher = true;
    } else {
        println!("Access denied");
    }
}

// TODO: if students not exist error : quentin
fn enter_grade() {
    println!("What is the name of the student?");
    let name: String = input().get();
    println!("What is the new grade of the student?");
    let grade: f32 = input().add_test(|x| *x >= 0.0 && *x <= 6.0).get();
    let mut map = DATABASE.lock().unwrap();
    match map.get_mut(&name) {
        Some(v) => v.push(grade),
        None => {
            map.insert(name, vec![grade]);
        }
    };
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

fn main() {
    welcome();
    let mut teacher = false;
    loop {
        menu(&mut teacher);
    }
}
