/*
 * (C) Copyright 2017-2018 Nuxeo (http://nuxeo.com/) and others.
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
 * Contributors:
 *     Guillaume Renard <grenard@nuxeo.com>
 */
package org.nuxeo.ecm.csv.core.operation;

import java.util.List;
import org.apache.commons.lang3.StringUtils;

import org.nuxeo.ecm.automation.core.Constants;
import org.nuxeo.ecm.automation.core.annotations.Context;
import org.nuxeo.ecm.automation.core.annotations.Operation;
import org.nuxeo.ecm.automation.core.annotations.OperationMethod;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.csv.core.CSVImportLog;
import org.nuxeo.ecm.csv.core.CSVImporter;
import org.nuxeo.runtime.api.Framework;

/**
 * @since 9.3
 */
@Operation(id = CSVImportLogOperation.ID, category = Constants.CAT_DOCUMENT, label = "CSVImportLog")
public class CSVImportLogOperation {

    public static final String ID = "CSV.ImportLog";

    @Context
    protected CoreSession mSession;

    @OperationMethod
    public List<CSVImportLog> getLog(String importID) {
        if (StringUtils.isEmpty(importID)) {
            return null;
        }
        CSVImporter csvImporter = Framework.getService(CSVImporter.class);
        return csvImporter.getImportLogs(importID);
    }
}
