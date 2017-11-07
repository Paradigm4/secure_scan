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

#include <memory>

#include <array/DBArray.h>
#include <array/Dense1MChunkEstimator.h>
#include <array/Metadata.h>
#include <array/TransientCache.h>
#include <query/Operator.h>
#include <system/SystemCatalog.h>

using namespace std;

namespace scidb
{
static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("scidb.secure_scan"));

class PhysicalSecureScan: public  PhysicalOperator
{
  public:
    PhysicalSecureScan(const std::string& logicalName,
                 const std::string& physicalName,
                 const Parameters& parameters,
                 const ArrayDesc& schema):
    PhysicalOperator(logicalName, physicalName, parameters, schema)
    {
        _arrayName = dynamic_pointer_cast<OperatorParamReference>(parameters[0])->getObjectName();

        // TODO
        _userId = -1;
        if (_parameters.size() == 3) {
            _userId = ((std::shared_ptr<OperatorParamPhysicalExpression>&)_parameters[2])->getExpression()->evaluate().getInt64();
        }
        LOG4CXX_DEBUG(logger, "secure_scan::userId:" << _userId);
    }

    virtual RedistributeContext getOutputDistribution(const std::vector<RedistributeContext> & inputDistributions,
                                                      const std::vector< ArrayDesc> & inputSchemas) const
    {
        ArrayDistPtr arrDist = _schema.getDistribution();
        SCIDB_ASSERT(arrDist);
        SCIDB_ASSERT(arrDist->getPartitioningSchema()!=psUninitialized);
        std::shared_ptr<Query> query(_query);
        SCIDB_ASSERT(query);
        if (query->isDistributionDegradedForRead(_schema)) {
            // make sure PhysicalSecureScan informs the optimizer that the distribution is unknown
            SCIDB_ASSERT(arrDist->getPartitioningSchema()!=psUndefined);
            //XXX TODO: psReplication declared as psUndefined would confuse SG because most of the data would collide.
            //XXX TODO: One option is to take the intersection between the array residency and the query live set
            //XXX TODO: (i.e. the default array residency) and advertize that as the new residency (with psReplicated)...
            ASSERT_EXCEPTION((arrDist->getPartitioningSchema()!=psReplication),
                             "Arrays with replicated distribution in degraded mode are not supported");

            // not  updating the schema, so that DBArray can succeed
            return RedistributeContext(createDistribution(psUndefined),
                                       _schema.getResidency());
        }
        return RedistributeContext(_schema.getDistribution(),
                                   _schema.getResidency());
    }

    virtual PhysicalBoundaries getOutputBoundaries(const std::vector<PhysicalBoundaries> & inputBoundaries,
                                                   const std::vector<ArrayDesc> & inputSchemas) const
    {
        Coordinates lowBoundary = _schema.getLowBoundary();
        Coordinates highBoundary = _schema.getHighBoundary();

        return PhysicalBoundaries(lowBoundary, highBoundary);
    }

    virtual void preSingleExecute(std::shared_ptr<Query> query)
    {
        if (_schema.isTransient())
        {
            query->isDistributionDegradedForWrite(_schema);
        }
    }

    std::shared_ptr< Array> execute(std::vector< std::shared_ptr< Array> >& inputArrays,
                                      std::shared_ptr<Query> query)
    {
        SCIDB_ASSERT(!_arrayName.empty());

        std::string arrayName;
        std::string namespaceName;
        query->getNamespaceArrayNames(_arrayName, namespaceName, arrayName);

        // Get permissions array.
        ArrayDesc permSchema;
        SystemCatalog::GetArrayDescArgs args;
        args.nsName = "permissions";
        args.arrayName = arrayName;
        args.catalogVersion = query->getCatalogVersion(args.nsName, args.arrayName);
        args.versionId = LAST_VERSION;
        args.throwIfNotFound = true;
        args.result = &permSchema;
        SystemCatalog::getInstance()->getArrayDesc(args);

        permSchema.setNamespaceName(args.nsName);
        LOG4CXX_DEBUG(logger, "secure_scan::permSchema:" << permSchema);

        std::shared_ptr<Array> permArray(DBArray::newDBArray(permSchema, query));
        LOG4CXX_DEBUG(logger, "secure_scan::permArray:" << permArray);


        // Get worker lock for transient arrays.
        if (_schema.isTransient() && !query->isCoordinator())
        {
            std::shared_ptr<LockDesc> lock(
                make_shared<LockDesc>(
                    namespaceName,
                    arrayName,
                    query->getQueryID(),
                    Cluster::getInstance()->getLocalInstanceId(),
                    LockDesc::WORKER,
                    LockDesc::XCL));

            Query::Finalizer f = bind(&UpdateErrorHandler::releaseLock, lock,_1);
            query->pushFinalizer(f);
            SystemCatalog::ErrorChecker errorChecker(bind(&Query::validate, query));
            if (!SystemCatalog::getInstance()->lockArray(lock, errorChecker)) {
                throw USER_EXCEPTION(SCIDB_SE_SYSCAT, SCIDB_LE_CANT_INCREMENT_LOCK)<< lock->toString();
            }
        }

        if (_schema.isAutochunked())
        {
            // Whether transient or not, scanning an array that is autochunked
            // in the system catalog gets you a non-autochunked empty MemArray.

            Dense1MChunkEstimator::estimate(_schema.getDimensions());
            return make_shared<MemArray>(_schema, query);
        }
        else if (_schema.isTransient())
        {
            MemArrayPtr a = transient::lookup(_schema,query);
            ASSERT_EXCEPTION(a.get()!=nullptr, string("Temp array ")+_schema.toString()+string(" not found"));
            return a;                                   // ...temp array
        }
        else
        {
            assert(_schema.getId() != 0);
            assert(_schema.getUAId() != 0);
            return std::shared_ptr<Array>(DBArray::newDBArray(_schema, query));
        }
    }

  private:
    string _arrayName;
    Coordinate _userId;
};

REGISTER_PHYSICAL_OPERATOR_FACTORY(PhysicalSecureScan, "secure_scan", "PhysicalSecureScan");

} //namespace scidb
