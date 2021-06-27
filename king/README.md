## SEC Project KING

Auteur: Gaëtan Daubresse, Quentin Saucy 

#### Authorization

The crate *Casbin* is used to control the authorization of the users. There is 3 different groups, *admin*, *teacher* and *student* that can respectively execute the *admin_action*, *teacher_action* or *student_action*. When the admin add a new user a line will automatically be added to the *king_policy.csv* file in order to give the correct access rights. 

#### Logs

The crate *simplelog* is used to handle the logs of the program. Each user actions are logged (wrong authentication, login, check grades, add new user, etc..). The name of the user executing the action is indicated in the logs. 

#### Authentication



#### Input validation

