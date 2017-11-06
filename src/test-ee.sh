#!/bin/bash


NS_SEC=secured
NS_PER=permissions
DATASET=dataset
DIM=${DATASET}_id
FLAG=access


set -o errexit

function cleanup {
    ## Cleanup
    iquery -A auth_root -anq "remove($NS_SEC.$DATASET)"  || true
    iquery -A auth_root -anq "drop_namespace('$NS_SEC')" || true
    iquery -A auth_root -anq "remove($NS_PER.$DATASET)"  || true
    iquery -A auth_root -anq "drop_namespace('$NS_PER')" || true
    iquery -A auth_root -anq "drop_user('todd')"         || true
    iquery -A auth_root -anq "drop_user('gary')"         || true
    rm auth_root auth_todd auth_gary test.expected test.out
}

trap cleanup EXIT


## Root Auth
cat <<EOF > auth_root
[security_password]
user-name=root
user-password=Paradigm4
EOF
chmod 0600 auth_root


## Init
iquery -A auth_root -aq "load_library('secure_scan')"
iquery -A auth_root -aq "create_namespace('$NS_SEC')"
iquery -A auth_root -aq "
    store(
      build(<val:string>[$DIM=0:10], '$DATASET_' + string($DIM)),
      $NS_SEC.$DATASET)"

iquery -A auth_root -aq "create_namespace('$NS_PER')"
iquery -A auth_root -aq "
    create array $NS_PER.$DATASET <$FLAG:bool>[user_id,$DIM]"


## Todd Auth
cat <<EOF > auth_todd
[security_password]
user-name=todd
user-password=bigsecret
EOF
chmod 0600 auth_todd
PWHASH=$(echo -n "bigsecret" | openssl dgst -sha512 -binary | base64 --wrap 0)
iquery -A auth_root -aq "create_user('todd', '"$PWHASH"')"


## Gary Auth
cat <<EOF > auth_gary
[security_password]
user-name=gary
user-password=topsecret
EOF
chmod 0600 auth_gary
PWHASH=$(echo -n "topsecret" | openssl dgst -sha512 -binary | base64 --wrap 0)
iquery -A auth_root -aq "create_user('gary', '"$PWHASH"')"


## Verify Users
cat <<EOF > test.expected
'scidbadmin'
'todd'
'gary'
EOF
iquery -A auth_root -o csv -aq "project(list('users'), name)" > test.out
diff test.out test.expected


# Gran Permissions
function grant () {
    iquery -A auth_root -aq "
        insert(
            redimension(
                apply(
                    filter(list('users'), name='$1'),
                    user_id, int64(id),
                    dataset_id, $2,
                    access, true),
                permissions.dataset),
            permissions.dataset);
        set_role_permissions('$1', 'namespace', '$NS_SEC', 'l')"
}

grant todd 1
grant todd 2
grant todd 3

grant gary 3
grant gary 4
grant gary 5


## Verify Permissions
cat <<EOF > test.expected
true,'todd',1
true,'todd',2
true,'todd',3
true,'gary',3
true,'gary',4
true,'gary',5
EOF
iquery -A auth_root -o csv -aq "
    apply(
        cross_join(
            permissions.dataset as D,
            redimension(
                apply(list('users'), user_id, int64(id)),
                <name:string>[user_id]) as U,
            D.user_id,
            U.user_id),
        dataset_id, dataset_id)" > test.out
diff test.out test.expected


## Verify Insufficient Permissioons
cat <<EOF > test.expected
UserException in file: src/namespaces/CheckAccess.cpp function: operator() line: 73
Error id: libnamespaces::SCIDB_SE_QPROC::NAMESPACE_E_INSUFFICIENT_PERMISSIONS
Error description: Query processor error. Insufficient permissions, need {[(ns:secured)r],} but only have {[(ns:public)clrud],[(ns:secured)l],}.
EOF

iquery -A auth_todd -aq "scan(secured.dataset)" > test.out 2>&1 || true
diff test.out test.expected

iquery -A auth_gary -aq "scan(secured.dataset)" > test.out 2>&1 || true
diff test.out test.expected


## Use secure_scan
iquery -A auth_todd -o csv:l -aq "op_count(secure_scan(secured.dataset))" > test.out
cat <<EOF > test.expected
count
11
EOF
diff test.out test.expected

iquery -A auth_gary -o csv:l -aq "op_count(secure_scan(secured.dataset))" > test.out
cat <<EOF > test.expected
count
11
EOF
diff test.out test.expected


exit 0
