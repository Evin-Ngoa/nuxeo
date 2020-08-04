/*
 * (C) Copyright 2020 Nuxeo (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.nuxeo.drive.mongodb;

import static org.nuxeo.ecm.platform.audit.api.BuiltinLogEntryData.LOG_ID;
import static org.nuxeo.ecm.platform.audit.api.BuiltinLogEntryData.LOG_LOG_DATE;
import static org.nuxeo.ecm.platform.audit.api.BuiltinLogEntryData.LOG_REPOSITORY_ID;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.nuxeo.drive.service.SynchronizationRoots;
import org.nuxeo.drive.service.impl.AuditChangeFinder;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.repository.RepositoryManager;
import org.nuxeo.ecm.core.query.sql.model.OrderByExprs;
import org.nuxeo.ecm.core.query.sql.model.Predicates;
import org.nuxeo.ecm.core.query.sql.model.QueryBuilder;
import org.nuxeo.ecm.platform.audit.api.AuditQueryBuilder;
import org.nuxeo.ecm.platform.audit.api.AuditReader;
import org.nuxeo.ecm.platform.audit.api.ExtendedInfo;
import org.nuxeo.ecm.platform.audit.api.LogEntry;
import org.nuxeo.mongodb.audit.MongoDBAuditBackend;
import org.nuxeo.mongodb.audit.MongoDBAuditEntryReader;
import org.nuxeo.runtime.api.Framework;

import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Sorts;

/**
 * Override the JPA audit based change finder to execute query in BSON.
 * <p>
 * The structure of the query executed by the {@link AuditChangeFinder} is:
 *
 * <pre>
 * from LogEntry log where log.repositoryId = :repositoryId
 *
 * + AND if ActiveRoots (activeRoots) NOT empty
 *
 * from LogEntry log where log.repositoryId = :repositoryId and (
 * LIST_DOC_EVENTS_IDS_QUERY and ( ROOT_PATHS or COLECTIONS_PATHS) or
 * (log.category = 'NuxeoDrive' and log.eventId != 'rootUnregistered') )
 *
 *
 * if ActiveRoots EMPTY:
 *
 * from LogEntry log where log.repositoryId = :repositoryId and ((log.category =
 * 'NuxeoDrive' and log.eventId != 'rootUnregistered'))
 *
 * + AND (log.id > :lowerBound and log.id <= :upperBound) + order by
 * log.repositoryId asc, log.eventDate desc
 * </pre>
 *
 * @since 11.2
 */
public class MongoDBAuditChangeFinder extends AuditChangeFinder {

    private static final Logger log = LogManager.getLogger(MongoDBAuditChangeFinder.class);

    @Override
    public long getUpperBound() {
        RepositoryManager repositoryManager = Framework.getService(RepositoryManager.class);
        return getUpperBound(new HashSet<>(repositoryManager.getRepositoryNames()));
    }

    /**
     * Returns the last available log id in the audit index considering events older than the last clustering
     * invalidation date if clustering is enabled for at least one of the given repositories. This is to make sure the
     * {@code DocumentModel} further fetched from the session using the audit entry doc id is fresh.
     */
    @Override
    @SuppressWarnings("unchecked")
    public long getUpperBound(Set<String> repositoryNames) {
        long clusteringDelay = getClusteringDelay(repositoryNames);
        AuditReader auditService = Framework.getService(AuditReader.class);
        // var params = new HashMap<String, Object>();
        // StringBuilder auditQuerySb = new StringBuilder("{\"$and\":[");
        QueryBuilder queryBuilder = new AuditQueryBuilder().predicate(
                Predicates.in(LOG_REPOSITORY_ID, repositoryNames));
        if (clusteringDelay > -1) {
            // Double the delay in case of overlapping, see https://jira.nuxeo.com/browse/NXP-14826
            long lastClusteringInvalidationDate = System.currentTimeMillis() - 2 * clusteringDelay;
            // params.put("lastClusteringInvalidationDate", new Date(lastClusteringInvalidationDate));
            // auditQuerySb.append("{logDate:{$lt:${lastClusteringInvalidationDate}}},");
            queryBuilder.and(Predicates.lt(LOG_LOG_DATE, lastClusteringInvalidationDate));
        }
        queryBuilder.order(OrderByExprs.desc(LOG_ID));
        queryBuilder.limit(1);
        // auditQuerySb.append("{$orderby:{id:-1}}]}");
        // var entries = (List<LogEntry>) auditService.nativeQuery(auditQuerySb.toString(), params, 1, 1);
        var entries = (List<LogEntry>) auditService.queryLogs(queryBuilder);

        if (entries.isEmpty()) {
            if (clusteringDelay > -1) {
                // Check for existing entries without the clustering invalidation date filter to not return -1 in this
                // case and make sure the lower bound of the next call to NuxeoDriveManager#getChangeSummary will be >=
                // 0
                List<LogEntry> allEntries = (List<LogEntry>) auditService.nativeQuery("", 1, 1);
                if (!allEntries.isEmpty()) {
                    log.debug("Found no audit log entries matching the criterias but some exist, returning 0");
                    return 0;
                }
            }
            log.debug("Found no audit log entries, returning -1");
            return -1;
        }
        return entries.get(0).getId();
    }

    @Override
    protected List<LogEntry> queryAuditEntries(CoreSession session, SynchronizationRoots activeRoots,
            Set<String> collectionSyncRootMemberIds, long lowerBound, long upperBound, int limit) {
        MongoDBAuditBackend auditService = (MongoDBAuditBackend) Framework.getService(AuditReader.class);
        MongoCollection<Document> auditCollection = auditService.getAuditCollection();
        StringBuilder queryBuilder = new StringBuilder();
        Map<String, Object> params = new HashMap<>();

        queryBuilder.append("{\n");
        queryBuilder.append("  \"$and\": [\n");
        queryBuilder.append("    {\n");
        queryBuilder.append("      \"repositoryId\": \"${repositoryId}\"\n");
        queryBuilder.append("    },\n");
        queryBuilder.append("    {\n");
        queryBuilder.append("      \"category\": \"eventDocumentCategory\"\n");
        queryBuilder.append("    },\n");
        queryBuilder.append("    {\n");
        queryBuilder.append("      \"$or\": [\n");
        queryBuilder.append("        {\n");
        queryBuilder.append("          \"$and\": [\n");
        queryBuilder.append("            {\n");
        queryBuilder.append("              \"category\": \"eventDocumentCategory\"\n");
        queryBuilder.append("            },\n");
        queryBuilder.append("            {\n");
        queryBuilder.append("              \"eventId\": {\n");
        queryBuilder.append("                \"$in\": [\n");
        queryBuilder.append("                  \"documentCreated\",\n");
        queryBuilder.append("                  \"documentModified\",\n");
        queryBuilder.append("                  \"documentMoved\",\n");
        queryBuilder.append("                  \"documentCreatedByCopy\",\n");
        queryBuilder.append("                  \"documentRestored\",\n");
        queryBuilder.append("                  \"addedToCollection\",\n");
        queryBuilder.append("                  \"documentProxyPublished\",\n");
        queryBuilder.append("                  \"documentLocked\",\n");
        queryBuilder.append("                  \"documentUnlocked\",\n");
        queryBuilder.append("                  \"documentUntrashed\"\n");
        queryBuilder.append("                ]\n");
        queryBuilder.append("              }\n");
        queryBuilder.append("            }\n");
        queryBuilder.append("          ]\n");
        queryBuilder.append("        }, \n");
        queryBuilder.append("        {\n");
        queryBuilder.append("          \"$and\": [\n");
        queryBuilder.append("            {\n");
        queryBuilder.append("              \"eventId\":  \"lifecycle_transition_event\"\n");
        queryBuilder.append("            },\n");
        queryBuilder.append("            {\n");
        queryBuilder.append("              \"docLifeCycle\": { \"$ne\": \"deleted\" }\n");
        queryBuilder.append("            }\n");
        queryBuilder.append("          ]\n");
        queryBuilder.append("        }\n");
        queryBuilder.append("      ]\n");
        queryBuilder.append("    },\n");
        queryBuilder.append("    {\n");
        queryBuilder.append("      \"$or\": [\n");
        if (!activeRoots.getPaths().isEmpty()) {
            queryBuilder.append(getCurrentRootFilteringClause(activeRoots.getPaths(), params) + "\n");
        }
        if (collectionSyncRootMemberIds != null && !collectionSyncRootMemberIds.isEmpty()) {
            queryBuilder.append(getCollectionSyncRootFilteringClause(collectionSyncRootMemberIds, params) + "\n");
        }
        queryBuilder.append("        {\n");
        queryBuilder.append("          \"$and\": [\n");
        queryBuilder.append("            {\n");
        queryBuilder.append("              \"category\": \"NuxeoDrive\"\n");
        queryBuilder.append("            },\n");
        queryBuilder.append("            {\n");
        queryBuilder.append("              \"eventId\": { \"$ne\": \"rootUnregistered\" }\n");
        queryBuilder.append("            }\n");
        queryBuilder.append("          ]\n");
        queryBuilder.append("        }\n");
        queryBuilder.append("      ]\n");
        queryBuilder.append("    },\n");
        queryBuilder.append("    {\n");
        queryBuilder.append("      \"$and\": [\n");
        queryBuilder.append("        {\n");
        queryBuilder.append("          \"id\": { \"gt\": \"${lowerBound}\" }\n");
        queryBuilder.append("        },\n");
        queryBuilder.append("        {\n");
        queryBuilder.append("          \"id\": { \"lte\": \"${upperBound}\" }\n");
        queryBuilder.append("        }\n");
        queryBuilder.append("      ]\n");
        queryBuilder.append("    }\n");
        queryBuilder.append("  ]\n");
        queryBuilder.append("}\n");

        Bson filter = auditService.buildFilter(queryBuilder.toString(), params);
        var sorts = List.of(Sorts.ascending("repositoryId"), Sorts.descending("eventDate"));
        var order = Sorts.orderBy(sorts);
        FindIterable<Document> iterable = auditCollection.find(filter).sort(order);
        List<LogEntry> entries = StreamSupport.stream(iterable.spliterator(), false)
                                              .map(MongoDBAuditEntryReader::read)
                                              .collect(Collectors.toList());

        // Post filter the output to remove (un)registration that are unrelated
        // to the current user.
        List<LogEntry> postFilteredEntries = new ArrayList<>();
        String principalName = session.getPrincipal().getName();
        for (LogEntry entry : entries) {
            ExtendedInfo impactedUserInfo = entry.getExtendedInfos().get("impactedUserName");
            if (impactedUserInfo != null && !principalName.equals(impactedUserInfo.getValue(String.class))) {
                // ignore event that only impact other users
                continue;
            }
            log.debug("Change detected: {}", entry);
            postFilteredEntries.add(entry);
        }
        return postFilteredEntries;
    }

    @Override
    protected String getCurrentRootFilteringClause(Set<String> rootPaths, Map<String, Object> params) {
        StringBuilder rootPathClause = new StringBuilder();
        int rootPathCount = 0;
        for (String rootPath : rootPaths) {
            rootPathCount++;
            String rootPathParam = "rootPath" + rootPathCount;
            // if (rootPathClause.length() > 0) {
            // rootPathClause.append(",");
            // }
            rootPathClause.append(String.format("{ \"docPath\": \"/${%s}.*/\" },", rootPathParam));
            params.put(rootPathParam, rootPath);

        }
        return rootPathClause.toString();
    }

    @Override
    protected String getCollectionSyncRootFilteringClause(Set<String> collectionSyncRootMemberIds,
            Map<String, Object> params) {
        String paramName = "collectionMemberIds";
        params.put(paramName, collectionSyncRootMemberIds);
        return String.format("{ \"docUUID\": { \"$in\": \"${collectionMemberIds}\" } },", paramName);
    }

}
