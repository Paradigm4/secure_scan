#!/bin/bash


NS_SEC=secured
NS_PER=permissions
DAT=dataset
DIM=${DAT}_id
FLAG=access


set -o errexit

function cleanup {
    echo "--- entering cleanup"
    ## Cleanup
    iquery -A auth_admin -anq "remove($NS_SEC.$DAT)"      || true
    iquery -A auth_admin -anq "drop_namespace('$NS_SEC')" || true

    iquery -A auth_admin -anq "remove($NS_PER.$DIM)"      || true
    iquery -A auth_admin -anq "drop_namespace('$NS_PER')" || true

    iquery -A auth_admin -anq "drop_user('todd')"         || true
    iquery -A auth_admin -anq "drop_user('gary')"         || true
    rm auth_admin auth_todd auth_gary test.expected test.out test2.out
}

trap cleanup EXIT


## Admin Auth
cat <<EOF > auth_admin
[security_password]
user-name=scidbadmin
user-password=Paradigm4
EOF
chmod 0600 auth_admin


## Create Namespaces
iquery -A auth_admin -aq "load_library('secure_scan')"
iquery -A auth_admin -aq "create_namespace('$NS_SEC')"
iquery -A auth_admin -aq "create_namespace('$NS_PER')"


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


## Create Data Array
iquery -A auth_admin -aq "
    store(
      build(<val:string>[$DIM=1:10:0:10], '${DAT}_' + string($DIM)),
      $NS_SEC.$DAT)"


## Grant Namespace List Permission
iquery -A auth_admin -aq "
   set_role_permissions('todd', 'namespace', '$NS_SEC', 'l');
   set_role_permissions('gary', 'namespace', '$NS_SEC', 'l')"


## 1. EXCEPTION: Temp permissions array
iquery -A auth_admin -aq "
    create temp array $NS_PER.$DIM <$FLAG:bool>[user_id;$DIM=1:10:0:10]"
iquery -A auth_todd -o csv:l -aq "secure_scan($NS_SEC.$DAT)" \
    2> test.out                                              \
    || true
cat test.out | grep -v "Failed query id:" > test2.out || true
cat <<EOF > test.expected
UserException in file: PhysicalSecureScan.cpp function: execute line: 118
Error id: scidb::SCIDB_SE_OPERATOR::SCIDB_LE_ILLEGAL_OPERATION
Error description: Operator error. Illegal operation: temporary permissions arrays not supported.
EOF
diff test2.out test.expected
iquery -A auth_admin -aq "remove($NS_PER.$DIM)"


## 2. EXCEPTION: Empty permissions array
iquery -A auth_admin -aq "
    create array $NS_PER.$DIM <$FLAG:bool>[user_id;$DIM=1:10:0:10]"
iquery -A auth_todd -o csv:l -aq "secure_scan($NS_SEC.$DAT)" \
    2> test.out                                              \
    || true
cat test.out | grep -v "Failed query id:" > test2.out || true
cat <<EOF > test.expected
UserException in file: PhysicalSecureScan.cpp function: execute line: 123
Error id: scidb::SCIDB_SE_OPERATOR::SCIDB_LE_ILLEGAL_OPERATION
Error description: Operator error. Illegal operation: auto-chunked permissions arrays not supported.
EOF
diff test2.out test.expected
iquery -A auth_admin -aq "remove($NS_PER.$DIM)"


## 3. EXCEPTION: No "user_id" dimension in permissions array
iquery -A auth_admin -aq "
    create array $NS_PER.$DIM <$FLAG:bool>[user_id_WRONG=0:0;$DIM=0:0];
    store(build($NS_PER.$DIM, true), $NS_PER.$DIM)"
iquery -A auth_todd -o csv:l -aq "secure_scan($NS_SEC.$DAT)" \
    2> test.out                                              \
    || true
cat test.out | grep -v "Failed query id:" > test2.out || true
cat <<EOF > test.expected
UserException in file: PhysicalSecureScan.cpp function: execute line: 163
Error id: scidb::SCIDB_SE_OPERATOR::SCIDB_LE_ILLEGAL_OPERATION
Error description: Operator error. Illegal operation: permissions array does not have an user ID dimension.
EOF
diff test2.out test.expected
iquery -A auth_admin -aq "remove($NS_PER.$DIM)"


## 4. EXCEPTION: No "dataset_id" dimension in permissions array
iquery -A auth_admin -aq "
    create array $NS_PER.$DIM <$FLAG:bool>[user_id=0:1;${DIM}_WRONG=0:1];
    store(build($NS_PER.$DIM, true), $NS_PER.$DIM)"
iquery -A auth_todd -o csv:l -aq "secure_scan($NS_SEC.$DAT)" \
    2> test.out                                              \
    || true
cat test.out | grep -v "Failed query id:" > test2.out || true
cat <<EOF > test.expected
UserException in file: PhysicalSecureScan.cpp function: execute line: 168
Error id: scidb::SCIDB_SE_OPERATOR::SCIDB_LE_ILLEGAL_OPERATION
Error description: Operator error. Illegal operation: permissions array does not have a permission dimension.
EOF
diff test2.out test.expected
iquery -A auth_admin -aq "remove($NS_PER.$DIM)"


## 5. EXCEPTION: No "dataset_id" dimension in data array
iquery -A auth_admin -aq "remove($NS_SEC.$DAT)"
iquery -A auth_admin -aq "
    store(
      build(<val:string>[${DIM}_WRONG=1:10:0:10], '${DAT}'),
      $NS_SEC.$DAT)"
todd_id=$(iquery -A auth_admin -o csv -aq "
    project(filter(list('users'), name='todd'), id)")
iquery -A auth_admin -aq "
    create array $NS_PER.$DIM <$FLAG:bool>[user_id=$todd_id:$todd_id;$DIM=0:0];
    store(build($NS_PER.$DIM, true), $NS_PER.$DIM)"
iquery -A auth_todd -o csv:l -aq "secure_scan($NS_SEC.$DAT)" \
    2> test.out                                              \
    || true
cat test.out | grep -v "Failed query id:" > test2.out || true
cat <<EOF > test.expected
UserException in file: PhysicalSecureScan.cpp function: execute line: 244
Error id: scidb::SCIDB_SE_OPERATOR::SCIDB_LE_ILLEGAL_OPERATION
Error description: Operator error. Illegal operation: scanned array does not have a permission dimension.
EOF
diff test2.out test.expected
iquery -A auth_admin -aq "remove($NS_PER.$DIM); remove($NS_SEC.$DAT)"


## Create Permissions Array
iquery -A auth_admin -aq "
    create array $NS_PER.$DIM <$FLAG:bool>[user_id;$DIM=1:10]"


## Create Data Array
iquery -A auth_admin -aq "
    create array $NS_SEC.$DAT <val:string>[$DIM=1:10:0:10]"


## Gran Permissions
function grant () {
    iquery -A auth_admin -aq "
        insert(
            redimension(
                apply(
                    filter(list('users'), name='$1'),
                    user_id, int64(id),
                    $DIM, $2,
                    access, $3),
                $NS_PER.$DIM),
            $NS_PER.$DIM)"
}

grant todd 1 true
grant todd 2 false
grant todd 3 true
grant todd 4 true


## 6. EXCEPTION: No permissions in the scanned array
iquery -A auth_gary -o csv:l -aq "secure_scan($NS_SEC.$DAT)" \
    2> test.out                                              \
    || true
cat test.out | grep -v "Failed query id:" > test2.out || true
cat <<EOF > test.expected
UserException in file: PhysicalSecureScan.cpp function: execute line: 239
Error id: scidb::SCIDB_SE_OPERATOR::SCIDB_LE_ILLEGAL_OPERATION
Error description: Operator error. Illegal operation: user has no permissions in the scanned array.
EOF
diff test2.out test.expected


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
            permissions.$DIM as D,
            redimension(
                apply(list('users'), user_id, int64(id)),
                <name:string>[user_id]) as U,
            D.user_id,
            U.user_id),
        $DIM, $DIM)" > test.out
cat test.out | grep -v "Failed query id:" > test2.out || true
diff test2.out test.expected


## Verify Insufficient Permissioons
cat <<EOF > test.expected
UserException in file: src/namespaces/CheckAccess.cpp function: operator() line: 73
Error id: libnamespaces::SCIDB_SE_QPROC::NAMESPACE_E_INSUFFICIENT_PERMISSIONS
Error description: Query processor error. Insufficient permissions, need {[(ns:$NS_SEC)r],} but only have {[(ns:public)clrud],[(ns:$NS_SEC)l],}.
EOF

iquery -A auth_todd -aq "scan($NS_SEC.$DAT)" > test.out 2>&1 || true
cat test.out | grep -v "Failed query id:" > test2.out || true
diff test2.out test.expected

iquery -A auth_gary -aq "scan($NS_SEC.$DAT)" > test.out 2>&1 || true
cat test.out | grep -v "Failed query id:" > test2.out || true
diff test2.out test.expected


## Use secure_scan
iquery -A auth_todd -o csv:l -aq "secure_scan($NS_SEC.$DAT)" > test.out
cat <<EOF > test.expected
val
EOF
diff test.out test.expected

iquery -A auth_gary -o csv:l -aq "secure_scan($NS_SEC.$DAT)" > test.out
cat <<EOF > test.expected
val
EOF
diff test.out test.expected


## Populate data array
iquery -A auth_admin -aq "
    store(
      build(<val:string>[$DIM=1:10:0:10], '${DAT}_' + string($DIM)),
      $NS_SEC.$DAT)"


## Use secure_scan
iquery -A auth_todd -o csv:l -aq "secure_scan($NS_SEC.$DAT)" > test.out
cat <<EOF > test.expected
val
'${DAT}_1'
'${DAT}_3'
'${DAT}_4'
EOF
diff test.out test.expected

iquery -A auth_gary -o csv:l -aq "secure_scan($NS_SEC.$DAT)" > test.out
cat <<EOF > test.expected
val
'${DAT}_2'
'${DAT}_3'
'${DAT}_5'
EOF
diff test.out test.expected


## Use secure_scan and op_count
iquery -A auth_todd -o csv:l -aq "op_count(secure_scan($NS_SEC.$DAT))" \
    > test.out
cat <<EOF > test.expected
count
3
EOF
diff test.out test.expected

iquery -A auth_gary -o csv:l -aq "op_count(secure_scan($NS_SEC.$DAT))" \
    > test.out
cat <<EOF > test.expected
count
3
EOF
diff test.out test.expected


## Use secure_scan and aggregate
iquery -A auth_todd -o csv:l -aq "
    aggregate(secure_scan($NS_SEC.$DAT), max(val))" \
    > test.out
cat <<EOF > test.expected
val_max
'dataset_4'
EOF
diff test.out test.expected

iquery -A auth_gary -o csv:l -aq "
    aggregate(secure_scan($NS_SEC.$DAT), max(val))" \
    > test.out
cat <<EOF > test.expected
val_max
'dataset_5'
EOF
diff test.out test.expected


## Use secure_scan and apply
iquery -A auth_todd -o csv:l -aq "
    apply(secure_scan($NS_SEC.$DAT), i, dataset_id, j, val)" \
    > test.out
cat <<EOF > test.expected
val,i,j
'dataset_1',1,'dataset_1'
'dataset_3',3,'dataset_3'
'dataset_4',4,'dataset_4'
EOF
diff test.out test.expected

iquery -A auth_gary -o csv:l -aq "
    apply(secure_scan($NS_SEC.$DAT), i, dataset_id, j, val)" \
    > test.out
cat <<EOF > test.expected
val,i,j
'dataset_2',2,'dataset_2'
'dataset_3',3,'dataset_3'
'dataset_5',5,'dataset_5'
EOF
diff test.out test.expected

echo "### PASSED ALL TESTS"

exit 0
