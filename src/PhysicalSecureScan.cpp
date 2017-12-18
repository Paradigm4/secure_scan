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
#include <query/Operator.h>
#include <rbac/Session.h>
#include <system/SystemCatalog.h>

#include "settings.h"
#include "BetweenArray.h"

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


    void inspectLogicalOp(LogicalOperator const& lop) override
    {
        setControlCookie(lop.getInspectable());
    }

    std::shared_ptr< Array> execute(std::vector< std::shared_ptr< Array> >& inputArrays,
                                    std::shared_ptr<Query> query)
    {
        SCIDB_ASSERT(!_arrayName.empty());
        SCIDB_ASSERT(_schema.getId() != 0);
        SCIDB_ASSERT(_schema.getUAId() != 0);

        // Get user ID
        Coordinate userId = query->getSession()->getUser().getId();
        LOG4CXX_DEBUG(logger, "secure_scan::userId:" << userId);

        // Get data array name
        std::string dataArrayName;
        std::string dataNSName;
        query->getNamespaceArrayNames(_arrayName, dataNSName, dataArrayName);

        // Get data array
        std::shared_ptr<Array> dataArray(DBArray::newDBArray(_schema, query));

        if (getControlCookie() == rbac::DBA_USER) {
          // Do privileged stuff
          LOG4CXX_DEBUG(logger, "secure_scan::privileged user");
          return dataArray;
        }

        // Get permissions array
        ArrayDesc permSchema;
        SystemCatalog::GetArrayDescArgs args;
        args.nsName = PERM_NS;
        args.arrayName = PERM_ARRAY;
        args.catalogVersion = query->getCatalogVersion(args.nsName, args.arrayName);
        args.versionId = LAST_VERSION;
        args.throwIfNotFound = true;
        args.result = &permSchema;
        SystemCatalog::getInstance()->getArrayDesc(args);
        if (permSchema.isTransient())
        {
            throw USER_EXCEPTION(SCIDB_SE_OPERATOR, SCIDB_LE_ILLEGAL_OPERATION)
                << "temporary permissions arrays not supported";
        }
        if (permSchema.isAutochunked()) // possibly empty
        {
            throw USER_EXCEPTION(SCIDB_SE_OPERATOR, SCIDB_LE_ILLEGAL_OPERATION)
                << "auto-chunked permissions arrays not supported";
        }

        permSchema.setNamespaceName(args.nsName);
        LOG4CXX_DEBUG(logger, "secure_scan::permSchema:" << permSchema);

        std::shared_ptr<Array> permArray(DBArray::newDBArray(permSchema, query));
        LOG4CXX_DEBUG(logger, "secure_scan::permArray:" << permArray);

        // Set cooridnates for permissions array
        Dimensions const& permDims = permSchema.getDimensions();
        size_t permNDims = permDims.size();
        Coordinates permCoordStart(permNDims);
        Coordinates permCoordEnd(permNDims);
        size_t permDimPermIdx;
        bool hasUserDim = false, hasPermDim = false;
        for (size_t i = 0; i < permNDims; i++)
        {
            if (permDims[i].hasNameAndAlias(USER_DIM))
            {
                hasUserDim = true;
                permCoordStart[i] = userId;
                permCoordEnd[i] = userId;
            }
            else
            {
                permCoordStart[i] = permDims[i].getStartMin();
                permCoordEnd[i] = permDims[i].getEndMax();
            }
            if (permDims[i].hasNameAndAlias(PERM_DIM))
            {
                hasPermDim = true;
                permDimPermIdx = i;
            }
            LOG4CXX_DEBUG(logger, "secure_scan::permCoordStart[" << i << "]:" << permCoordStart[i]);
            LOG4CXX_DEBUG(logger, "secure_scan::permCoordEnd[" << i << "]:" << permCoordEnd[i]);
        }
        if (!hasUserDim)
        {
            throw USER_EXCEPTION(SCIDB_SE_OPERATOR, SCIDB_LE_ILLEGAL_OPERATION)
                << "permissions array does not have an user ID dimension";
        }
        if (!hasPermDim)
        {
            throw USER_EXCEPTION(SCIDB_SE_OPERATOR, SCIDB_LE_ILLEGAL_OPERATION)
                << "permissions array does not have a permission dimension";
        }

        // Build spatial range for permissions array
        SpatialRangesPtr permSpatialRangesPtr = make_shared<SpatialRanges>(permNDims);
        permSpatialRangesPtr->insert(SpatialRange(permCoordStart, permCoordEnd));
        permSpatialRangesPtr->buildIndex();

        // Add between for permissions array
        std::shared_ptr<Array> permBetweenArray(
            make_shared<BetweenArray>(permSchema,
                                      permSpatialRangesPtr,
                                      permArray));
        LOG4CXX_DEBUG(logger, "secure_scan::permBetweenArray:" << permBetweenArray);

        // Redistribute permissions array
        std::shared_ptr<Array> permRedistArray = redistributeToRandomAccess(
            permBetweenArray,
            createDistribution(psReplication),
            permSchema.getResidency(),
            query,
            getShared(),
            true);

        // Set cooridnates for data array
        Dimensions const& dataDims = _schema.getDimensions();
        size_t dataNDims = dataDims.size();
        Coordinates dataCoordStart(dataNDims);
        Coordinates dataCoordEnd(dataNDims);

        // Build spatial range for data array
        SpatialRangesPtr dataSpatialRangesPtr = make_shared<SpatialRanges>(dataNDims);
        shared_ptr<ConstArrayIterator> aiter = permRedistArray->getConstIterator(0);
        hasPermDim = false;
        while (!aiter->end())
        {
            ConstChunk const* chunk = &(aiter->getChunk());
            shared_ptr<ConstChunkIterator> citer =
                chunk->getConstIterator(ConstChunkIterator::IGNORE_OVERLAPS
                                        | ConstChunkIterator::IGNORE_EMPTY_CELLS);
            while (!citer->end())
            {
                if (citer->getItem().getBool())
                {
                    Coordinates const permCoord = citer->getPosition();

                    for (size_t i = 0; i < dataNDims; i++)
                    {
                        if (dataDims[i].hasNameAndAlias(PERM_DIM))
                        {
                            hasPermDim = true;
                            dataCoordStart[i] = permCoord[permDimPermIdx];
                            dataCoordEnd[i] = permCoord[permDimPermIdx];
                        }
                        else
                        {
                            dataCoordStart[i] = dataDims[i].getStartMin();
                            dataCoordEnd[i] = dataDims[i].getEndMax();
                        }
                        LOG4CXX_DEBUG(logger, "secure_scan::dataCoordStart[" << i << "]:" << dataCoordStart[i]);
                        LOG4CXX_DEBUG(logger, "secure_scan::dataCoordEnd[" << i << "]:" << dataCoordEnd[i]);
                    }
                    dataSpatialRangesPtr->insert(SpatialRange(dataCoordStart, dataCoordEnd));
                }
                ++(*citer);
            }
            ++(*aiter);
        }
        if (dataSpatialRangesPtr->ranges().size() == 0)
        {
            throw USER_EXCEPTION(SCIDB_SE_OPERATOR, SCIDB_LE_ILLEGAL_OPERATION)
                << "user has no permissions in the scanned array";
        }
        if (!hasPermDim)
        {
            throw USER_EXCEPTION(SCIDB_SE_OPERATOR, SCIDB_LE_ILLEGAL_OPERATION)
                << "scanned array does not have a permission dimension";
        }
        dataSpatialRangesPtr->buildIndex();

        // Add between for data array
        std::shared_ptr<Array> dataBetweenArray(
            make_shared<BetweenArray>(_schema, dataSpatialRangesPtr, dataArray));

        return dataBetweenArray;
    }

  private:
    string _arrayName;
};

REGISTER_PHYSICAL_OPERATOR_FACTORY(PhysicalSecureScan, "secure_scan", "PhysicalSecureScan");

} //namespace scidb
