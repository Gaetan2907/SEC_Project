## SEC Project KING

Auteur: Gaëtan Daubresse, Quentin Saucy 

### Code Analysis



### TODO

#### Requirement

- Use Casbin to authenticate the users
  - Different file for every student 
  - Casbin control access to these files 
- Add admin account
  - Can create teacher and student 
  - Teacher can't add students themselves
- Use password
  - How to become teacher ? Shared secret between client and server ? 
  - When teacher register new student, the student receives an e-mail with init password
- Input validation user name
- Logging 
  - info : login success, ... 
  - warn : login failed, ..
- We suppose that the server is secured => Grades not encrypted on the server



#### Bonus

- Reset password by users