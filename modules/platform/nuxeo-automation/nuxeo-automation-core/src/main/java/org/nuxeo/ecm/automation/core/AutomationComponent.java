/*
 * (C) Copyright 2015-2017 Nuxeo (http://nuxeo.com/) and others.
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
 *     bstefanescu
 *     Vladimir Pasquier <vpasquier@nuxeo.com>
 */
package org.nuxeo.ecm.automation.core;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.management.InstanceAlreadyExistsException;
import javax.management.InstanceNotFoundException;
import javax.management.JMException;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.NotCompliantMBeanException;
import javax.management.ObjectName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.automation.scripting.api.AutomationScriptingService;
import org.nuxeo.automation.scripting.internals.AutomationScriptingParamsInjector;
import org.nuxeo.automation.scripting.internals.AutomationScriptingRegistry;
import org.nuxeo.automation.scripting.internals.AutomationScriptingServiceImpl;
import org.nuxeo.automation.scripting.internals.ClassFilterDescriptor;
import org.nuxeo.automation.scripting.internals.ScriptingOperationDescriptor;
import org.nuxeo.automation.scripting.internals.ScriptingOperationTypeImpl;
import org.nuxeo.ecm.automation.AutomationAdmin;
import org.nuxeo.ecm.automation.AutomationFilter;
import org.nuxeo.ecm.automation.AutomationService;
import org.nuxeo.ecm.automation.ChainException;
import org.nuxeo.ecm.automation.OperationException;
import org.nuxeo.ecm.automation.OperationParameters;
import org.nuxeo.ecm.automation.TypeAdapter;
import org.nuxeo.ecm.automation.context.ContextHelperDescriptor;
import org.nuxeo.ecm.automation.context.ContextHelperRegistry;
import org.nuxeo.ecm.automation.context.ContextService;
import org.nuxeo.ecm.automation.context.ContextServiceImpl;
import org.nuxeo.ecm.automation.core.events.EventHandler;
import org.nuxeo.ecm.automation.core.events.EventHandlerRegistry;
import org.nuxeo.ecm.automation.core.exception.ChainExceptionFilter;
import org.nuxeo.ecm.automation.core.exception.ChainExceptionImpl;
import org.nuxeo.ecm.automation.core.impl.ChainTypeImpl;
import org.nuxeo.ecm.automation.core.impl.OperationServiceImpl;
import org.nuxeo.ecm.automation.core.trace.TracerFactory;
import org.nuxeo.ecm.core.api.NuxeoException;
import org.nuxeo.ecm.platform.forms.layout.api.WidgetDefinition;
import org.nuxeo.ecm.platform.forms.layout.descriptors.WidgetDescriptor;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.runtime.management.ServerLocator;
import org.nuxeo.runtime.model.ComponentContext;
import org.nuxeo.runtime.model.ComponentInstance;
import org.nuxeo.runtime.model.DefaultComponent;
import org.nuxeo.runtime.services.config.ConfigurationService;

/**
 * Nuxeo component that provide an implementation of the {@link AutomationService} and handle extensions registrations.
 *
 * @author <a href="mailto:bs@nuxeo.com">Bogdan Stefanescu</a>
 * @author <a href="mailto:grenard@nuxeo.com">Guillaume Renard</a>
 */
public class AutomationComponent extends DefaultComponent {

    private static final Log log = LogFactory.getLog(AutomationComponent.class);

    public static final String XP_OPERATIONS = "operations";

    public static final String XP_ADAPTERS = "adapters";

    public static final String XP_CHAINS = "chains";

    public static final String XP_EVENT_HANDLERS = "event-handlers";

    public static final String XP_CHAIN_EXCEPTION = "chainException";

    public static final String XP_AUTOMATION_FILTER = "automationFilter";

    public static final String XP_CONTEXT_HELPER = "contextHelpers";

    protected static final String XP_SCRIPTED_OPERATION = "operation";

    protected static final String XP_CLASSFILTER = "classFilter";

    protected OperationServiceImpl service;

    protected EventHandlerRegistry handlers;

    protected TracerFactory tracerFactory;

    protected ContextHelperRegistry contextHelperRegistry;

    protected ContextService contextService;

    protected AutomationScriptingServiceImpl scriptingService;

    protected AutomationScriptingRegistry scriptingRegistry;

    protected final List<ClassFilterDescriptor> classFilterDescriptors = new ArrayList<>();

    @Override
    public void activate(ComponentContext context) {
        service = new OperationServiceImpl();
        tracerFactory = new TracerFactory();
        handlers = new EventHandlerRegistry(service);
        contextHelperRegistry = new ContextHelperRegistry();
        contextService = new ContextServiceImpl(contextHelperRegistry);
        scriptingService = new AutomationScriptingServiceImpl();
        scriptingRegistry = new AutomationScriptingRegistry();
        scriptingRegistry.automation = Framework.getService(AutomationService.class);
        scriptingRegistry.scripting = scriptingService;
        classFilterDescriptors.clear();
    }

    protected void bindManagement() throws JMException {
        ObjectName objectName = new ObjectName("org.nuxeo.automation:name=tracerfactory");
        MBeanServer mBeanServer = Framework.getService(ServerLocator.class).lookupServer();
        mBeanServer.registerMBean(tracerFactory, objectName);
    }

    protected void unBindManagement() throws MalformedObjectNameException, NotCompliantMBeanException,
            InstanceAlreadyExistsException, MBeanRegistrationException, InstanceNotFoundException {
        final ObjectName on = new ObjectName("org.nuxeo.automation:name=tracerfactory");
        final ServerLocator locator = Framework.getService(ServerLocator.class);
        if (locator != null) {
            MBeanServer mBeanServer = locator.lookupServer();
            mBeanServer.unregisterMBean(on);
        }
    }

    @Override
    public void deactivate(ComponentContext context) {
        service = null;
        handlers = null;
        tracerFactory = null;
    }

    @Override
    public void registerContribution(Object contribution, String extensionPoint, ComponentInstance contributor) {
        if (XP_OPERATIONS.equals(extensionPoint)) {
            OperationContribution opc = (OperationContribution) contribution;
            List<WidgetDefinition> widgetDefinitionList = new ArrayList<>();
            if (opc.widgets != null) {
                for (WidgetDescriptor widgetDescriptor : opc.widgets) {
                    widgetDefinitionList.add(widgetDescriptor.getWidgetDefinition());
                }
            }
            Class<?> type;
            try {
                type = Class.forName(opc.type);
            } catch (ClassNotFoundException e) {
                throw new IllegalArgumentException("Invalid operation class '" + opc.type + "': class not found.");
            }
            try {
                service.putOperation(type, opc.replace, contributor.getName().toString(), widgetDefinitionList);
            } catch (OperationException e) {
                throw new RuntimeException(e);
            }
        } else if (XP_CHAINS.equals(extensionPoint)) {
            OperationChainContribution occ = (OperationChainContribution) contribution;
            try {
                ChainTypeImpl docChainType = new ChainTypeImpl(service,
                        occ.toOperationChain(contributor.getContext().getBundle()), occ,
                        contributor.getName().toString());
                List<OperationParameters> opps = docChainType.getChain().getOperations();
                for (OperationParameters opp : opps) {
                    if (!service.hasOperation(opp.id())) {
                        throw new OperationException("Operation with id '" + opp.id() + "' could not be found.");
                    }
                }
                service.putOperation(docChainType, occ.replace);
            } catch (OperationException e) {
                throw new RuntimeException(e);
            }
        } else if (XP_CHAIN_EXCEPTION.equals(extensionPoint)) {
            ChainExceptionDescriptor chainExceptionDescriptor = (ChainExceptionDescriptor) contribution;
            ChainException chainException = new ChainExceptionImpl(chainExceptionDescriptor);
            service.putChainException(chainException);
        } else if (XP_AUTOMATION_FILTER.equals(extensionPoint)) {
            AutomationFilterDescriptor automationFilterDescriptor = (AutomationFilterDescriptor) contribution;
            ChainExceptionFilter chainExceptionFilter = new ChainExceptionFilter(automationFilterDescriptor);
            service.putAutomationFilter(chainExceptionFilter);
        } else if (XP_ADAPTERS.equals(extensionPoint)) {
            TypeAdapterContribution tac = (TypeAdapterContribution) contribution;
            TypeAdapter adapter;
            try {
                adapter = tac.clazz.getDeclaredConstructor().newInstance();
            } catch (ReflectiveOperationException e) {
                throw new RuntimeException(e);
            }
            service.putTypeAdapter(tac.accept, tac.produce, adapter);
        } else if (XP_EVENT_HANDLERS.equals(extensionPoint)) {
            EventHandler eh = (EventHandler) contribution;
            if (eh.isPostCommit()) {
                handlers.putPostCommitEventHandler(eh);
            } else {
                handlers.putEventHandler(eh);
            }
        } else if (XP_CONTEXT_HELPER.equals(extensionPoint)) {
            contextHelperRegistry.addContribution((ContextHelperDescriptor) contribution);
        } else if (XP_SCRIPTED_OPERATION.equals(extensionPoint)) {
            ScriptingOperationDescriptor desc = (ScriptingOperationDescriptor) contribution;
            desc.setContributingComponent(contributor.getName().toString());
            ScriptingOperationTypeImpl type = new ScriptingOperationTypeImpl(scriptingService, service, desc);
            try {
                service.putOperation(type, true);
            } catch (OperationException e) {
                throw new NuxeoException("Cannot register scripting operation " + desc.getId(), e);
            }
        } else if (XP_CLASSFILTER.equals(extensionPoint)) {
            registerClassFilter((ClassFilterDescriptor) contribution);
        } else {
            log.error("Unknown extension point " + extensionPoint);
        }
    }

    @Override
    public void unregisterContribution(Object contribution, String extensionPoint, ComponentInstance contributor) {
        if (XP_OPERATIONS.equals(extensionPoint)) {
            try {
                Class<?> type = Class.forName(((OperationContribution) contribution).type);
                service.removeOperation(type);
            } catch (ClassNotFoundException e) {
                // ignore
            }
        } else if (XP_CHAINS.equals(extensionPoint)) {
            OperationChainContribution occ = (OperationChainContribution) contribution;
            service.removeOperationChain(occ.getId());
        } else if (XP_CHAIN_EXCEPTION.equals(extensionPoint)) {
            ChainExceptionDescriptor chainExceptionDescriptor = (ChainExceptionDescriptor) contribution;
            ChainException chainException = new ChainExceptionImpl(chainExceptionDescriptor);
            service.removeExceptionChain(chainException);
        } else if (XP_AUTOMATION_FILTER.equals(extensionPoint)) {
            AutomationFilterDescriptor automationFilterDescriptor = (AutomationFilterDescriptor) contribution;
            AutomationFilter automationFilter = new ChainExceptionFilter(automationFilterDescriptor);
            service.removeAutomationFilter(automationFilter);
        } else if (XP_ADAPTERS.equals(extensionPoint)) {
            TypeAdapterContribution tac = (TypeAdapterContribution) contribution;
            service.removeTypeAdapter(tac.accept, tac.produce);
        } else if (XP_EVENT_HANDLERS.equals(extensionPoint)) {
            EventHandler eh = (EventHandler) contribution;
            if (eh.isPostCommit()) {
                handlers.removePostCommitEventHandler(eh);
            } else {
                handlers.removeEventHandler(eh);
            }
        } else if (XP_CONTEXT_HELPER.equals(extensionPoint)) {
            contextHelperRegistry.removeContribution((ContextHelperDescriptor) contribution);
        } else if (XP_SCRIPTED_OPERATION.equals(extensionPoint)) {
            ScriptingOperationTypeImpl type = new ScriptingOperationTypeImpl(scriptingService, service,
                    (ScriptingOperationDescriptor) contribution);
            service.removeOperation(type);
        } else if (XP_CLASSFILTER.equals(extensionPoint)) {
            unregisterClassFilter((ClassFilterDescriptor) contribution);
        } else {
            log.error("Unknown extension point " + extensionPoint);
        }
    }

    protected void registerClassFilter(ClassFilterDescriptor desc) {
        classFilterDescriptors.add(desc);
        recomputeClassFilters();
    }

    protected void unregisterClassFilter(ClassFilterDescriptor desc) {
        classFilterDescriptors.remove(desc);
        recomputeClassFilters();
    }

    protected void recomputeClassFilters() {
        Set<String> allowedClassNames = new HashSet<>();
        for (ClassFilterDescriptor desc : classFilterDescriptors) {
            if (desc.deny.contains("*")) {
                allowedClassNames.clear();
                allowedClassNames.addAll(desc.allow);
            } else {
                allowedClassNames.addAll(desc.allow);
                allowedClassNames.removeAll(desc.deny);
            }
        }
        // we don't care about update atomicity, as nothing executes concurrently with XML config
        scriptingService.allowedClassNames.clear();
        scriptingService.allowedClassNames.addAll(allowedClassNames);
    }

    @Override
    public <T> T getAdapter(Class<T> adapter) {
        if (adapter == AutomationService.class || adapter == AutomationAdmin.class) {
            return adapter.cast(service);
        }
        if (adapter == EventHandlerRegistry.class) {
            return adapter.cast(handlers);
        }
        if (adapter == TracerFactory.class) {
            return adapter.cast(tracerFactory);
        }
        if (adapter == ContextService.class) {
            return adapter.cast(contextService);
        }
        if (adapter.isAssignableFrom(AutomationScriptingService.class)) {
            return adapter.cast(scriptingService);
        }
        return null;
    }

    @Override
    public void start(ComponentContext context) {
        boolean inlinedContext = Framework.getService(ConfigurationService.class)
                                          .isBooleanTrue("nuxeo.automation.scripting.inline-context-in-params");
        scriptingService.paramsInjector = AutomationScriptingParamsInjector.newInstance(inlinedContext);

        if (!tracerFactory.getRecordingState()) {
            log.info("You can activate automation trace mode to get more informations on automation executions");
        }
        try {
            bindManagement();
        } catch (JMException e) {
            throw new RuntimeException("Cannot bind management", e);
        }
    }

    @Override
    public void stop(ComponentContext context) {
        service.flushCompiledChains();
        try {
            unBindManagement();
        } catch (JMException e) {
            throw new RuntimeException("Cannot unbind management", e);
        }
    }
}
