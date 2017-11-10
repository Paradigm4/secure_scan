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
#include <system/SystemCatalog.h>

#include "query/ops/between/BetweenArray.h"
#include "query/ops/cross_join/CrossJoinArray.h"

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
        if (_parameters.size() == 2) {
            _userId = ((std::shared_ptr<OperatorParamPhysicalExpression>&)_parameters[1])->getExpression()->evaluate().getInt64();
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

        // Set cooridnates for permissions array
        Dimensions const& permDims = permSchema.getDimensions();
        size_t permNDims = permDims.size();
        Coordinates permCoordStart(permNDims);
        Coordinates permCoordEnd(permNDims);
        size_t permExtraDim = -1;
        for (size_t i = 0; i < permNDims; i++)
        {
            if (permDims[i].hasNameAndAlias("user_id"))
            {
                permCoordStart[i] = _userId;
                permCoordEnd[i] = _userId;
                permExtraDim = i;
            }
            else
            {
                permCoordStart[i] = permDims[i].getStartMin();
                permCoordEnd[i] = permDims[i].getEndMax();
            }
            LOG4CXX_DEBUG(logger, "secure_scan::permCoordStart[" << i << "]:" << permCoordStart[i]);
            LOG4CXX_DEBUG(logger, "secure_scan::permCoordEnd[" << i << "]:" << permCoordEnd[i]);
        }
        assert(permExtraDim >= 0);

        // Build spatial range
        SpatialRangesPtr permSpatialRangesPtr = make_shared<SpatialRanges>(permNDims);
        permSpatialRangesPtr->insert(SpatialRange(permCoordStart, permCoordEnd));
        permSpatialRangesPtr->buildIndex();

        // Add between
        std::shared_ptr<Array> permBetweenArray(
            make_shared<BetweenArray>(permSchema, permSpatialRangesPtr, permArray));
        LOG4CXX_DEBUG(logger, "secure_scan::permBetweenArray:" << permBetweenArray);

        // Set join dimensions
        Dimensions const& dataDims = _schema.getDimensions();
        size_t dataNDims = dataDims.size();
        vector<int> dataJoinDims(dataNDims, -1); // Left
        vector<int> permJoinDims(permNDims, -1); // Right

        int ref = -1;
        for (size_t i = 0; i < dataNDims; i++)
        {
            if (dataDims[i].hasNameAndAlias("dataset_id"))
            {
                dataJoinDims[i] = 0;
                ref = i;
                LOG4CXX_DEBUG(logger, "secure_scan::dataDims[" << i << "]:" << dataDims[i]);
            }
            LOG4CXX_DEBUG(logger, "secure_scan::dataJoinDims[" << i << "]:" << dataJoinDims[i]);
        }
        assert(ref >= 0);

        for (size_t i = 0; i < permNDims; i++)
        {
            if (permDims[i].hasNameAndAlias("dataset_id"))
            {
                permJoinDims[i] = ref;
                LOG4CXX_DEBUG(logger, "secure_scan::permDims[" << i << "]:" << permDims[i]);
            }
            LOG4CXX_DEBUG(logger, "secure_scan::permJoinDims[" << i << "]:" << permJoinDims[i]);
        }

        // Set join schema
        // - Dimensions
        Dimensions joinDims(dataNDims + 1);
        for (size_t i = 0; i< dataNDims; i++)
        {
            joinDims[i] = dataDims[i];
            LOG4CXX_DEBUG(logger, "secure_scan::joinDims[" << i << "]:" << joinDims[i]);
        }
        joinDims[dataNDims] = permDims[permExtraDim];
        LOG4CXX_DEBUG(logger, "secure_scan::joinDims[" << dataNDims << "]:" << joinDims[dataNDims]);

        // - Attributes
        Attributes const& dataAttrs = _schema.getAttributes();    // Left
        Attributes const& permAttrs = permSchema.getAttributes(); // Right
        size_t dataNAttrs = dataAttrs.size();
        size_t permNAttrs = permAttrs.size();
        size_t joinNAttrs = dataNAttrs + permNAttrs;
        AttributeDesc const* dataAttrBitmap = _schema.getEmptyBitmapAttribute();    // Left
        AttributeDesc const* permAttrBitmap = permSchema.getEmptyBitmapAttribute(); // Right
        if (dataAttrBitmap && permAttrBitmap)
        {
            joinNAttrs -= 1;
        }
        Attributes joinAttrs(joinNAttrs);
        AttributeID j = 0;
        for (size_t i = 0; i < dataNAttrs; i++)
        {
            AttributeDesc const& attr = dataAttrs[i];
            if (!attr.isEmptyIndicator())
            {
                joinAttrs[j] = AttributeDesc(j,
                                             attr.getName(),
                                             attr.getType(),
                                             attr.getFlags(),
                                             attr.getDefaultCompressionMethod(),
                                             attr.getAliases(),
                                             &attr.getDefaultValue(),
                                             attr.getDefaultValueExpr());
                // no addAlias
                LOG4CXX_DEBUG(logger, "secure_scan::(1)joinAttrs[" << j << "]:" << joinAttrs[j]);
                j += 1;
            }
        }
        for (size_t i = 0; i < permNAttrs; i++)
        {
            AttributeDesc const& attr = permAttrs[i];
            joinAttrs[j] = AttributeDesc(j,
                                         attr.getName(),
                                         attr.getType(),
                                         attr.getFlags(),
                                         attr.getDefaultCompressionMethod(),
                                         attr.getAliases(),
                                         &attr.getDefaultValue(),
                                         attr.getDefaultValueExpr());
            // no addAlias
            LOG4CXX_DEBUG(logger, "secure_scan::(2)joinAttrs[" << j << "]:" << joinAttrs[j]);
            j += 1;
        }
        if (dataAttrBitmap && !permAttrBitmap)
        {
            AttributeDesc const& attr = *dataAttrBitmap;
            joinAttrs[j] = AttributeDesc(j,
                                         attr.getName(),
                                         attr.getType(),
                                         attr.getFlags(),
                                         attr.getDefaultCompressionMethod(),
                                         attr.getAliases(),
                                         &attr.getDefaultValue(),
                                         attr.getDefaultValueExpr());
            // no addAlias
            LOG4CXX_DEBUG(logger, "secure_scan::(3)joinAttrs[" << j << "]:" << joinAttrs[j]);
            j += 1;
        }
        // - ArrayDesc (Schema)
        ArrayDesc joinSchema(_schema.getName(),
                             joinAttrs,
                             joinDims,
                             _schema.getDistribution(),
                             _schema.getResidency());

        if (_schema.isAutochunked())
        {
            // TODO

            // Whether transient or not, scanning an array that is autochunked
            // in the system catalog gets you a non-autochunked empty MemArray.

            Dense1MChunkEstimator::estimate(_schema.getDimensions());
            return make_shared<MemArray>(_schema, query);
        }
        else
        {
            assert(_schema.getId() != 0);
            assert(_schema.getUAId() != 0);

            std::shared_ptr<Array> dataArray(DBArray::newDBArray(_schema, query));

            // Add CrossJoin
            std::shared_ptr<Array> joinArray(
                make_shared<CrossJoinArray>(joinSchema,
                                            dataArray,
                                            permBetweenArray,
                                            dataJoinDims,
                                            permJoinDims));
            LOG4CXX_DEBUG(logger, "secure_scan::joinArray:" << joinArray);

            return joinArray;
        }
    }

  private:
    string _arrayName;
    Coordinate _userId;
};

REGISTER_PHYSICAL_OPERATOR_FACTORY(PhysicalSecureScan, "secure_scan", "PhysicalSecureScan");

} //namespace scidb
