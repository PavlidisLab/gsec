/*
 * The Gemma project
 *
 * Copyright (c) 2008 University of British Columbia
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package gemma.gsec.acl.afterinvocation;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AfterInvocationProvider;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.afterinvocation.AbstractAclProvider;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;

import gemma.gsec.SecurityService;
import gemma.gsec.acl.ValueObjectAwareIdentityRetrievalStrategyImpl;
import gemma.gsec.model.Securable;

/**
 * Filter out public {@link Securables}s, leaving only ones that the user specifically can view but aren't public. This
 * includes data sets that are read-only for the user, e.g. shared by another user
 *
 * @author keshav
 * @version $Id: AclAfterFilterCollectionForMyPrivateData.java,v 1.4 2013/09/14 16:56:02 paul Exp $
 * @see AfterInvocationProvider
 */
public class AclAfterFilterCollectionForMyPrivateData extends AbstractAclProvider {

    private final Log log = LogFactory.getLog( this.getClass() );

    @Autowired
    private SecurityService securityService;

    public AclAfterFilterCollectionForMyPrivateData( AclService aclService, List<Permission> requirePermission ) {
        super( aclService, "AFTER_ACL_FILTER_MY_PRIVATE_DATA", requirePermission );
        this.setObjectIdentityRetrievalStrategy( new ValueObjectAwareIdentityRetrievalStrategyImpl() );

    }

    /*
     * (non-Javadoc)
     *
     * @seeorg.springframework.security.afterinvocation.AfterInvocationProvider#decide(org.springframework.security.
     * Authentication, java.lang.Object, org.springframework.security.ConfigAttributeDefinition, java.lang.Object)
     */
    @Override
    @SuppressWarnings("unchecked")
    public final Object decide( Authentication authentication, Object object, Collection<ConfigAttribute> config,
            Object returnedObject ) throws AccessDeniedException {
        Iterator<ConfigAttribute> iter = config.iterator();

        while ( iter.hasNext() ) {
            ConfigAttribute attr = iter.next();

            if ( this.supports( attr ) ) {
                // Need to process the Collection for this invocation
                if ( returnedObject == null ) {
                    log.debug( "Return object is null, skipping" );

                    return null;
                }

                Filterer<Object> filterer = null;

                boolean wasSingleton = false;
                if ( returnedObject instanceof Collection ) {
                    Collection<Object> collection = ( Collection<Object> ) returnedObject;
                    filterer = new CollectionFilterer<>( collection );
                } else if ( returnedObject.getClass().isArray() ) {
                    Object[] array = ( Object[] ) returnedObject;
                    filterer = new ArrayFilterer<>( array );
                } else {
                    // shortcut, just put the object in a collection. (PP)
                    wasSingleton = true;
                    Collection<Object> coll = new HashSet<>();
                    coll.add( returnedObject );
                    filterer = new CollectionFilterer<>( coll );
                }

                // Locate unauthorised Collection elements
                Iterator<Object> collectionIter = filterer.iterator();

                /*
                 * Collect up the securables
                 */
                Collection<Securable> securablesToFilter = new HashSet<>();
                while ( collectionIter.hasNext() ) {
                    Object domainObject = collectionIter.next();
                    if ( !Securable.class.isAssignableFrom( domainObject.getClass() ) ) {
                        continue;
                    }
                    securablesToFilter.add( ( Securable ) domainObject );
                }

                /*
                 * Do it like this cuz it's wayyyy faster.
                 */
                Map<Securable, Boolean> ownership = securityService
                        .areNonPublicButReadableByCurrentUser( securablesToFilter );

                for ( Securable s : ownership.keySet() ) {
                    if ( !ownership.containsKey( s ) || !ownership.get( s ) ) {
                        filterer.remove( s );
                    }

                    if ( !hasPermission( authentication, s ) ) {
                        filterer.remove( s );
                    }
                }

                if ( wasSingleton ) {
                    if ( ( ( Collection<Object> ) filterer.getFilteredObject() ).size() == 1 ) {
                        return ( ( Collection<Object> ) filterer.getFilteredObject() ).iterator().next();
                    }
                    return null;

                }
                return filterer.getFilteredObject();
            }
        }

        return returnedObject;
    }

}
