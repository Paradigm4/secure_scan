#!/bin/bash


NS_SEC=secured
NS_PER=permissions
DATASET=dataset
DIM=${DATASET}_id
FLAG=access


set -o errexit

function cleanup {
    ## Cleanup
    iquery -A auth_admin -anq "remove($NS_SEC.$DATASET)"  || true
    iquery -A auth_admin -anq "drop_namespace('$NS_SEC')" || true
    iquery -A auth_admin -anq "remove($NS_PER.$DATASET)"  || true
    iquery -A auth_admin -anq "drop_namespace('$NS_PER')" || true
    iquery -A auth_admin -anq "drop_user('todd')"         || true
    iquery -A auth_admin -anq "drop_user('gary')"         || true
    rm auth_admin auth_todd auth_gary test.expected test.out
}

trap cleanup EXIT


## Admin Auth
cat <<EOF > auth_admin
[security_password]
user-name=scidbadmin
user-password=Paradigm4
EOF
chmod 0600 auth_admin


## Init
iquery -A auth_admin -aq "load_library('secure_scan')"
iquery -A auth_admin -aq "create_namespace('$NS_SEC')"
iquery -A auth_admin -aq "
    store(
      build(<val:string>[$DIM=1:10:0:10], '${DATASET}_' + string($DIM)),
      $NS_SEC.$DATASET)"

iquery -A auth_admin -aq "create_namespace('$NS_PER')"
iquery -A auth_admin -aq "
    create array $NS_PER.$DATASET <$FLAG:bool>[user_id,$DIM=1:10:0:10]"


## Todd Auth
cat <<EOF > auth_todd
[security_password]
user-name=todd
user-password=bigsecret
EOF
chmod 0600 auth_todd
PWHASH=$(echo -n "bigsecret" | openssl dgst -sha512 -binary | base64 --wrap 0)
iquery -A auth_admin -aq "create_user('todd', '"$PWHASH"')"


## Gary Auth
cat <<EOF > auth_gary
[security_password]
user-name=gary
user-password=topsecret
EOF
chmod 0600 auth_gary
PWHASH=$(echo -n "topsecret" | openssl dgst -sha512 -binary | base64 --wrap 0)
iquery -A auth_admin -aq "create_user('gary', '"$PWHASH"')"


## Verify Users
cat <<EOF > test.expected
'scidbadmin'
'todd'
'gary'
EOF
iquery -A auth_admin -o csv -aq "project(list('users'), name)" > test.out
diff test.out test.expected


# Gran Permissions
function grant () {
    iquery -A auth_admin -aq "
        insert(
            redimension(
                apply(
                    filter(list('users'), name='$1'),
                    user_id, int64(id),
                    dataset_id, $2,
                    access, $3),
                $NS_PER.$DATASET),
            $NS_PER.$DATASET);
        set_role_permissions('$1', 'namespace', '$NS_SEC', 'l')"
}

grant todd 1 true
grant todd 2 false
grant todd 3 true
grant todd 4 true

grant gary 2 true
grant gary 3 true
grant gary 4 false
grant gary 5 true


## Verify Permissions
cat <<EOF > test.expected
true,'todd',1
false,'todd',2
true,'todd',3
true,'todd',4
true,'gary',2
true,'gary',3
false,'gary',4
true,'gary',5
EOF
iquery -A auth_admin -o csv -aq "
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
iquery -A auth_todd -o csv:l -aq "secure_scan(secured.dataset)" > test.out
cat <<EOF > test.expected
val
'dataset_1'
'dataset_3'
'dataset_4'
EOF
diff test.out test.expected

iquery -A auth_gary -o csv:l -aq "secure_scan(secured.dataset)" > test.out
cat <<EOF > test.expected
val
'dataset_2'
'dataset_3'
'dataset_5'
EOF
diff test.out test.expected


exit 0
