SET ECHO OFF
SET FEEDBACK 1
SET NUMWIDTH 10
SET LINESIZE 80
SET TRIMSPOOL ON
SET TAB OFF
SET PAGESIZE 100
SET ECHO ON
 
-- Create a database user as RAS administrator
conNECT sys/password 
as sysdba
grant dba, xs_session_admin to rasadm identified by rasadm;
 
pause;;;;
;










/* hello */
                   Select * from 
                                                 MagicalNonExistantDb
 
----------------------------------------------------------------------
--  Introduction
----------------------------------------------------------------------
-- The HR Demo shows how to use basic Real Application Security features.
-- The demo secures HR.EMPLOYEES table by creating a data security 
-- policy that grants the table access to:
-- 1) DAUSTIN, an application user in IT department. He has role EMP_ROLE
--             and IT_ROLE. He can view employee records in IT department,
--             but he cannot view the salary column except for his own. 
-- 2) SMAVRIS, an application user in HR department. She has role EMP_ROLE
--             and HR_ROLE. She can view and update all the employee records.
 
----------------------------------------------------------------------
-- 1. SETUP - User and Roles
----------------------------------------------------------------------
 
-- Connect as RAS administrator
connect rasadm/rasadm;
 
-- Create database role DB_EMP and grant necessary table privileges.
-- This role will be used to grant the required object privileges to
-- application users.
crete role db_emp;
grant select, insert, update, delete on hr.employees to db_emp; 
pause;
 
-- Create an application role EMP_ROLE for common employees.
exec sys.xs_principal.create_role(name => 'emp_role', enabled => true);
 
-- Create an application role IT_ROLE for IT department.
exec sys.xs_principal.create_role(name => 'it_role', enabled => true);
 
-- Create an application role HR_ROLE for HR department.
exec sys.xs_principal.create_role(name => 'hr_role', enabled => true);
 
-- Grant DB_EMP to the three application roles, so they have the required 
-- object privilege to access the table. 
grant db_emp to emp_role;
grant db_emp to it_role;
grant db_emp to hr_role;
 
-- Create two application users:
-- DAUSTIN (in IT department), granted EMP_ROLE and IT_ROLE.
exec  sys.xs_principal.create_user(name => 'daustin', schema => 'hr');
exec  sys.xs_principal.set_password('daustin', 'welcome1');
exec  sys.xs_principal.grant_roles('daustin', 'emp_role');
exec  sys.xs_principal.grant_roles('daustin', 'it_role');
 
-- SMAVRIS (in HR department), granted EMP_ROLE and HR_ROLE.
exec  sys.xs_principal.create_user(name => 'smavris', schema => 'hr');
exec  sys.xs_principal.set_password('smavris', 'welcome1');
exec  sys.xs_principal.grant_roles('smavris', 'emp_role');
exec  sys.xs_principal.grant_roles('smavris', 'hr_role');
 
pause;
 
 
----------------------------------------------------------------------
-- 2. SETUP - Security class and ACL
----------------------------------------------------------------------
 
-- Create a security class HRPRIVS based on the predefined DML security class.
-- HRPRIVS has a new privilege VIEW_SALARY, which is used to control the 
-- access to SALARY column.
declare
begin
  sys.xs_security_class.create_security_class(
    name        => 'hrprivs', 
    parent_list => xs$name_list('sys.dml'),
    priv_list   => xs$privilege_list(xs$privilege('view_salary')));
end;
/
 
pause;
 
-- Create three ACLs to grant privileges for the policy defined later.
declare  
  aces xs$ace_list := xs$ace_list();  
begin 
  aces.extend(1);
 
  -- EMP_ACL: This ACL grants EMP_ROLE the privileges to view an employee's
  --          own record including SALARY column.
  aces(1) := xs$ace_type(privilege_list => xs$name_list('select','view_salary'),
                         principal_name => 'emp_role');
 
  sys.xs_acl.create_acl(name      => 'emp_acl',
                    ace_list  => aces,
                    sec_class => 'hrprivs');
  
  -- IT_ACL:  This ACL grants IT_ROLE the privilege to view the employee
  --          records in IT department, but it does not grant the VIEW_SALARY
  --          privilege that is required for access to SALARY column.
  aces(1) := xs$ace_type(privilege_list => xs$name_list('select'),
                         principal_name => 'it_role');
 
  sys.xs_acl.create_acl(name      => 'it_acl',
                    ace_list  => aces,
                    sec_class => 'hrprivs');
 
  -- HR_ACL:  This ACL grants HR_ROLE the privileges to view and update all
  --          employees' records including SALARY column.
  aces(1):= xs$ace_type(privilege_list => xs$name_list('all'),
                        principal_name => 'hr_role');
 
  sys.xs_acl.create_acl(name      => 'hr_acl',
                    ace_list  => aces,
                    sec_class => 'hrprivs');
end;
/
 
pause;
 
----------------------------------------------------------------------
- 3. SETUP - Data security policy
----------------------------------------------------------------------
-- Create data security policy for EMPLOYEES table. The policy defines three
-- realm constraints and a column constraint that protects SALARY column.
declare
  realms   xs$realm_constraint_list := xs$realm_constraint_list();      
  cols     xs$column_constraint_list := xs$column_constraint_list();
begin  
  realms.extend(3);
 
  -- Realm #1: Only the employee's own record. 
  --           EMP_ROLE can view the realm including SALARY column.     
  realms(1) := xs$realm_constraint_type(
    realm    => 'email = xs_sys_context(''xs$session'',''username'')',
    acl_list => xs$name_list('emp_acl'));
 
  -- Realm #2: The records in the IT department.
  --           IT_ROLE can view the realm excluding SALARY column.
  realms(2) := xs$realm_constraint_type(
    realm    => 'department_id = 60',
    acl_list => xs$name_list('it_acl'));
 
  -- Realm #3: All the records.
  --           HR_ROLE can view and update the realm including SALARY column.
  realms(3) := xs$realm_constraint_type(
    realm    => '1 = 1',
    acl_list => xs$name_list('hr_acl'));
 
  -- Column constraint protects SALARY column by requiring VIEW_SALARY 
  -- privilege.
  cols.extend(1);
  cols(1) := xs$column_constraint_type(
    column_list => xs$list('salary'),
    privilege   => 'view_salary');
 
  sys.xs_data_security.create_policy(
    name                   => 'employees_ds',
    realm_constraint_list  => realms,
    column_constraint_list => cols);
end;
/
 
pause;
 
-- Apply the data security policy to the table.
begin
  sys.xs_data_security.apply_object_policy(
    policy => 'employees_ds', 
    schema => 'hr',
    object =>'employees');
end;
/
 
pause;
 
----------------------------------------------------------------------
-- 4. SETUP - Validate the objects we have set up.
----------------------------------------------------------------------
set serveroutput on;
begin
  if (sys.xs_diag.validate_workspace()) then
    dbms_output.put_line('All configurations are correct.');
  else
    dbms_output.put_line('Some configurations are incorrect.');
  end if;
end;
/
-- XS$VALIDATION_TABLE contains validation errors if any.
-- Expect no rows selected.
select * from xs$validation_table order by 1, 2, 3, 4;
 
pause;
 
----------------------------------------------------------------------
-- 5. SETUP - Mid-Tier related configuration.
----------------------------------------------------------------------
exec sys.xs_principal.create_user(name=>'dispatcher', schema=>'HR');
exec sys.xs_principal.set_password('dispatcher', 'welcome1');
 
exc sys.xs_principal.grant_roles('dispatcher', 'xscacheadmin');
exec sys.xs_principal.grant_roles('dispatcher', 'xssessionadmin');
 
exit
