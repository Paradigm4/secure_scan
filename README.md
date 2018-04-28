Infer access permissions from permissions array and enforce on a data array.

# Summary

For a quick-start to what this operator aims to achieve, jump [here](https://github.com/Paradigm4/secure_scan/blob/master/README.md#now-the-desired-behavior-of-secure_scan-operator).

For a full description of how to set up the environment, read on below.

# Setup

The following will allow root scidb user to
use `iquery -aq` instead of writing `iquery --auth-file=/PATH/TO/CREDS -aq`

```sh
vi ~/.config/scidb/iquery.conf
```

Put in the following
```
{
"auth-file":"/home/scidb/.scidb_root_auth"
}
```

# Create test data

```sh
SECURE_NMSP="secured"
DATA_ARR="DATASET"
dimname="dataset_id"
iquery -aq "create_namespace('$SECURE_NMSP')"
iquery -aq "store(
              build(<name: string>[$dimname=0:3],
                   '[\'study 0\', \'study 1\', \'study 2\', \'study 3\']', true),
              $SECURE_NMSP.$DATA_ARRAY)"
```

# Create some test users

## user 'Todd'

```sh
vi ~/.scidb_todd_auth
```

Put in the following
```
[security_password]
user-name=Todd
user-password=bigsecret
```

More setup work (full doc for creating users [here](https://paradigm4.atlassian.net/wiki/spaces/ESD169/pages/50856096/Creating+Users))
```sh
chmod 600 ~/.scidb_todd_auth
PWHASH=$(echo -n "bigsecret" | openssl dgst -sha512 -binary | base64 --wrap 0)
iquery -aq "create_user('Todd', '"$PWHASH"')"
```

## user 'Gary'

```sh
vi ~/.scidb_gary_auth
```

Put in the following
```
[security_password]
user-name=Gary
user-password=biggersecret
```

More setup work (full doc for creating users [here](https://paradigm4.atlassian.net/wiki/spaces/ESD169/pages/50856096/Creating+Users))
```sh
chmod 600 ~/.scidb_gary_auth
PWHASH=$(echo -n "biggersecret" | openssl dgst -sha512 -binary | base64 --wrap 0)
iquery -aq "create_user('Gary', '"$PWHASH"')"
```

## Get user-ids from scidb

```sh
iquery -aq "list('users')"
# {No} name,id
# {0} 'root',1
# {1} 'Todd',2
# {2} 'Gary',3
```

# Now the permissions

We write the permissions to read the secure DATASET array in another namespace `PERMISSIONS`

```sh
PERMISSIONS_NMSP='PERMISSIONS'
iquery -aq "create_namespace('$PERMISSIONS_NMSP')"
```

Within this namespace, we start with one array that lists permissions for each user, at different `dataset_id`-s.

```sh
PERMISSIONS_ARRAY=$dimname
FLAG_NAME="access_allowed"
iquery -aq "create array $PERMISSIONS_NMSP.$PERMISSIONS_ARRAY <$FLAG_NAME:bool>[user_id,$PERMISSIONS_ARRAY]"
```

Note that we chose to have one dimension to have the same name as the array.

Now let us create a function to add permissions for users at distinct datasets

```sh
give_user_access_at_dataset_id () {
   iquery -aq "insert(
     redimension(
       apply(project(filter(list('users'), name='$1'),id),
             user_id, int64(id),
             $dimname, int64($2),
             $FLAG_NAME, true), $PERMISSIONS_NMSP.$PERMISSIONS_ARRAY),
    $PERMISSIONS_NMSP.$PERMISSIONS_ARRAY)"
} 
```

Now let us add permissions for some users

```sh
give_user_access_at_dataset_id Todd 2
give_user_access_at_dataset_id Gary 1
give_user_access_at_dataset_id Gary 3
```

At this point, the permissions array should look like this

```sh
{user_id,dataset_id} access_allowed
{2,2} true
{3,1} true
{3,3} true
```
# Now the desired behavior of `secure_scan` operator

## Regular scan operator

Since the users `Gary` and `Todd` have not explicitly been given permissions to the
secured namespace, they should not be able to see any data in DATASET using regular
methods (more details [here](https://paradigm4.atlassian.net/wiki/spaces/ESD169/pages/50856054/Roles+and+Permissions)).

```sh
iquery --auth-file=/home/scidb/.scidb_todd_auth -aq "scan($SECURE_NMSP.$DATA_ARRAY)"
# UserException in file: src/namespaces/CheckAccess.cpp function: operator() line: 73
# Error id: libnamespaces::SCIDB_SE_QPROC::NAMESPACE_E_INSUFFICIENT_PERMISSIONS
# Error description: Query processor error. Insufficient permissions, need {[(ns:secured)r],} but only have {[(ns:public)clrud],}.

iquery --auth-file=/home/scidb/.scidb_gary_auth -aq "scan($SECURE_NMSP.$DATA_ARRAY)"
# ..
# Error id: libnamespaces::SCIDB_SE_QPROC::NAMESPACE_E_INSUFFICIENT_PERMISSIONS
# Error description: Query processor error. Insufficient permissions, need {[(ns:secured)r],} but only have {[(ns:public)clrud],}.
```

## `secure_scan` operator

This operator should infer user permissions from the PERMISSIONS.dataset_id array and only show those rows.

**RECAP**

```sh
iquery -aq "list('users')"
# {No} name,id
# {0} 'root',1
# {1} 'Todd',2
# {2} 'Gary',3

iquery -aq "scan($PERMISSIONS_NMSP.$PERMISSIONS_ARRAY)"
# {user_id,dataset_id} access_allowed
# {2,2} true
# {3,1} true
# {3,3} true

iquery -aq "scan($SECURE_NMSP.$DATA_ARRAY)"
# {dataset_id} name
# {0} 'study 0'
# {1} 'study 1'
# {2} 'study 2'
# {3} 'study 3'
```

**Desired output**

User 'Todd' has access to study 2 only

```sh
iquery --auth-file=/home/scidb/.scidb_todd_auth -aq "secure_scan($SECURE_NMSP.$DATA_ARRAY)"
# {2} 'study 2'
````

User 'Gary' has access to studies 1 and 3
```sh
iquery --auth-file=/home/scidb/.scidb_todd_auth -aq "secure_scan($SECURE_NMSP.$DATA_ARRAY)"
{1} 'study 1'
{3} 'study 3'
````

# Generalization

## 1. Enforce one permissions array across multiple data arrays

Above we enforced permissions for the dimension `dataset_id` in an array `secured.DATASET` using
permissions in `PERMISSIONS.dataset_id`.

The permissions array will be reused to enforce permissions in other data arrays in the `secured`
namespace e.g. arrays like:

```sh
VARIANT <reference_allele: string, ...>
      [dataset_id, dataset_version, variantset_id, biosample_id, feature_id, variant_synth_id]
RNAQUANTIFICATION <value:float>
      [dataset_id, dataset_version, rnaquantificationset_id, biosample_id, feature_id]
```

## 2. Enforce multiple permissions array into one data array

(This one is lower priority, and is written here for descriptive purposes)

If there is another permissions array

```sh
PERMISSIONS.dataset_version <access_allowed:bool>[user_id, dataset_version]
```

Then the `secure_scan` operator would enforce permissions for both dimensions in an array like
`VARIANT` or `RNAQUANTIFICATION` above.

# Corner cases

## 1. Permissions added for dataset-s that do not exist, or have been deleted

```sh
give_user_access_at_dataset_id Todd 5

# should not change output as dataset 5 has not been added
iquery --auth-file=/home/scidb/.scidb_todd_auth -aq "secure_scan($SECURE_NMSP.$DATA_ARRAY)"
# {2} 'study 2'
```

# Cleanup

```sh
iquery -aq "remove($SECURE_NMSP.$DATA_ARRAY)"
iquery -aq "remove($PERMISSIONS_NMSP.$PERMISSIONS_ARRAY)"
```
