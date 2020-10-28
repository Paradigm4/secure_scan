/*
**
* BEGIN_COPYRIGHT
*
* Copyright (C) 2008-2017 SciDB, Inc.
* All Rights Reserved.
*
* secure_scan is a plugin for SciDB, an Open Source Array DBMS maintained
* by Paradigm4. See http://www.paradigm4.com/
*
* secure_scan is free software: you can redistribute it and/or modify
* it under the terms of the AFFERO GNU General Public License as published by
* the Free Software Foundation.
*
* secure_scan is distributed "AS-IS" AND WITHOUT ANY WARRANTY OF ANY KIND,
* INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY,
* NON-INFRINGEMENT, OR FITNESS FOR A PARTICULAR PURPOSE. See
* the AFFERO GNU General Public License for the complete license terms.
*
* You should have received a copy of the AFFERO GNU General Public License
* along with secure_scan.  If not, see <http://www.gnu.org/licenses/agpl-3.0.html>
*
* END_COPYRIGHT
*/

#include <log4cxx/logger.h>
#include <array/ArrayName.h>
#include <query/LogicalOperator.h>
#include <query/Query.h>
#include <query/Transaction.h>
#include <query/UserQueryException.h>
#include <rbac/NamespacesCommunicator.h>
#include <rbac/Rights.h>
#include <rbac/Session.h>

#include "settings.h"

using namespace std;
using namespace scidb::namespaces;

namespace scidb
{
    static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("scidb.secure_scan"));

/**
 * @brief The operator: secure_scan().
 *
 * @par Synopsis:
 *   secure_scan( srcArray )
 *
 * @par Summary:
 *   Produces a result array that is equivalent to a stored array.
 *
 * @par Input:
 *   - srcArray: the array to scan, with srcAttrs and srcDims.
 *
 * @par Output array:
 *        <
 *   <br>   srcAttrs
 *   <br> >
 *   <br> [
 *   <br>   srcDims
 *   <br> ]
 *
 * @par Examples:
 *   n/a
 *
 * @par Errors:
 *   n/a
 *
 * @par Notes:
 *   n/a
 *
 */
class LogicalSecureScan: public  LogicalOperator
{
private:
    std::string _privInfo;

public:
    LogicalSecureScan(const std::string& logicalName, const std::string& alias):
                    LogicalOperator(logicalName, alias)
    {
    }

    static PlistSpec const* makePlistSpec()
    {
        static PlistSpec argSpec {
            { "", // positionals
              RE(RE::LIST, {
                 RE(PP(PLACEHOLDER_ARRAY_NAME).setAllowVersions(true)),
                 RE(RE::QMARK, {
                    RE(PP(PLACEHOLDER_CONSTANT, TID_BOOL))
                 })
              })
            }
        };
        return &argSpec;
    }

    void inferAccess(const std::shared_ptr<Query>& query) override
    {
        LogicalOperator::inferAccess(query);

        SCIDB_ASSERT(!_parameters.empty());
        SCIDB_ASSERT(_parameters.front()->getParamType() == PARAM_ARRAY_REF);

        const string& arrayNameOrig =
            ((std::shared_ptr<OperatorParamReference>&)
             _parameters.front())->getObjectName();
        SCIDB_ASSERT(isNameUnversioned(arrayNameOrig));

        ArrayDesc srcDesc;
        SystemCatalog::GetArrayDescArgs args;
        query->getNamespaceArrayNames(arrayNameOrig, args.nsName, args.arrayName);
        args.throwIfNotFound = true;
        args.result = &srcDesc;
        SystemCatalog::getInstance()->getArrayDesc(args);
        if (srcDesc.isTransient())
        {
            throw USER_EXCEPTION(SCIDB_SE_OPERATOR, SCIDB_LE_ILLEGAL_OPERATION)
                << "temporary arrays not supported";
        }

        if (srcDesc.isAutochunked())
        {
            throw USER_EXCEPTION(SCIDB_SE_OPERATOR, SCIDB_LE_ILLEGAL_OPERATION)
                << "auto-chunked arrays not supported";
        }

        auto lock = LockDesc::create(
                                     PERM_NS,
                                     PERM_ARRAY,
                                     query->getTxn(),
                                     LockDesc::COORD,
                                     LockDesc::RD);
        std::shared_ptr<LockDesc> resLock = query->getTxn().requestLock(lock);
        SCIDB_ASSERT(resLock);
        SCIDB_ASSERT(resLock->getLockMode() >= LockDesc::RD);
        /*        const LockDesc::LockMode lockMode = LockDesc::RD;
        std::shared_ptr<LockDesc>  lock(
            make_shared<LockDesc>(
                PERM_NS,
                PERM_ARRAY,
                query->getQueryID(),
                Cluster::getInstance()->getLocalInstanceId(),
                LockDesc::COORD,
                lockMode));
        std::shared_ptr<LockDesc> resLock = query->getTxn().requestLock(lock);
        SCIDB_ASSERT(resLock);
        SCIDB_ASSERT(resLock->getLockMode() >= LockDesc::RD);*/

        rbac::RightsMap neededRights;
        neededRights.upsert(rbac::ET_NAMESPACE, args.nsName, rbac::P_NS_READ);
        try {
          scidb::namespaces::Communicator::checkAccess(query->getSession().get(),
                                                       &neededRights);
          query->getRights()->upsert(rbac::ET_NAMESPACE, args.nsName, rbac::P_NS_READ);
        } catch (...) {
          query->getRights()->upsert(rbac::ET_NAMESPACE, args.nsName, rbac::P_NS_LIST);
        }
    }

    ArrayDesc inferSchema(std::vector< ArrayDesc> inputSchemas, std::shared_ptr< Query> query)
    {
        assert(inputSchemas.size() == 0);
        assert(_parameters.size() == 1);
        assert(_parameters[0]->getParamType() == PARAM_ARRAY_REF);

        std::shared_ptr<OperatorParamArrayReference>& arrayRef = (std::shared_ptr<OperatorParamArrayReference>&)_parameters[0];
        assert(arrayRef->getArrayName().empty() || ArrayDesc::isNameUnversioned(arrayRef->getArrayName()));
        assert(ArrayDesc::isNameUnversioned(arrayRef->getObjectName()));

        if (arrayRef->getVersion() == ALL_VERSIONS) {
            throw USER_QUERY_EXCEPTION(SCIDB_SE_INFER_SCHEMA, SCIDB_LE_WRONG_ASTERISK_USAGE2, _parameters[0]->getParsingContext());
        }
        ArrayDesc schema;
        const std::string &arrayNameOrig = arrayRef->getObjectName();

        SystemCatalog::GetArrayDescArgs args;
        query->getNamespaceArrayNames(arrayNameOrig, args.nsName, args.arrayName);
        args.catalogVersion = query->getTxn().getCatalogVersion(args.nsName, args.arrayName);
        args.versionId = arrayRef->getVersion();
        args.throwIfNotFound = true;
        args.result = &schema;
        SystemCatalog::getInstance()->getArrayDesc(args);

        schema.addAlias(arrayNameOrig);
        schema.setNamespaceName(args.nsName);

        SCIDB_ASSERT(not isUninitialized(schema.getDistribution()->getDistType()));
        SCIDB_ASSERT(not isUndefined(schema.getDistribution()->getDistType()));

        // Check if user has scidbadmin role
        if (query->getSession()->getUser().isDbAdmin()) {
            // Easy case: it's scidbadmin.  May as well use the
            // well-known DBA_USER string to signal that we have
            // privs.
            _privInfo = rbac::DBA_USER;
        } else {
            // Harder case: need to find out if they are assigned to
            // the "admin" role.  Make a temporary Rights object and
            // check to see if we have the rights.
            rbac::RightsMap neededRights;
            neededRights.upsert(rbac::ET_DB, "", rbac::P_DB_ADMIN);
            try {
                scidb::namespaces::Communicator::checkAccess(query->getSession().get(),
                                                             &neededRights);
                _privInfo = rbac::DBA_USER;    // Succeeded, user must
                                               // have the admin role.
            } catch (...) {
                // checkAccess threw, too bad for yew!
            }
        }

        // Check if user has read access on the namespace
        if (_privInfo != rbac::DBA_USER) { // only check if user does
                                           // not have scidbadmin role
            rbac::RightsMap neededRights;
            neededRights.upsert(rbac::ET_NAMESPACE, args.nsName, rbac::P_NS_READ);
            try {
                scidb::namespaces::Communicator::checkAccess(query->getSession().get(),
                                                             &neededRights);
                _privInfo = READ_PERM; // Succeeded, user must have
                                       // the read permission on
                                       // namespace.
            } catch (...) {
                // checkAccess threw, too bad for yew!
            }
        }

        return schema;
    }

    std::string getInspectable() const override
    {
        return _privInfo;
    }
};

REGISTER_LOGICAL_OPERATOR_FACTORY(LogicalSecureScan, "secure_scan");

} //namespace scidb
