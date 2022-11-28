/*
 * The Gemma project
 *
 * Copyright (c) 2012 University of British Columbia
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package gemma.gsec.util;

import org.hibernate.engine.spi.CascadeStyle;
import org.hibernate.persister.collection.CollectionPersister;
import org.hibernate.persister.entity.EntityPersister;

/**
 * @author paul
 * @version $Id: CrudUtils.java,v 1.8 2012/01/26 00:32:23 paul Exp $
 */
public interface CrudUtils {

    /**
     * @param role
     * @return
     */
    CollectionPersister getCollectionPersister( String role );

    /**
     * @param object
     * @return
     */
    EntityPersister getEntityPersister( Object object );

    /**
     * Determine if cascading an association is required.
     *
     * @param m method name
     * @param cs
     * @return true if the method would result in the action being taken on the associated entities.
     */
    boolean needCascade( String m, CascadeStyle cs );

    /**
     * @return true if the cascade style will result in a
     */
    boolean willCascade( CascadeStyle cs );

}