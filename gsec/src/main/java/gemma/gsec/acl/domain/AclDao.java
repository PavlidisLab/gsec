/*
 * The gemma-mda project
 *
 * Copyright (c) 2013 University of British Columbia
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
package gemma.gsec.acl.domain;

import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.ChildrenExistException;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nullable;
import java.util.List;

/**
 * @author Paul
 * @version $Id: AclDao.java,v 1.1 2013/09/14 16:55:19 paul Exp $
 */
public interface AclDao extends LookupStrategy {

    /**
     * Find an ACL object identity confirming to the given object identity.
     * <p>
     * If the provided object as a non-null ID, it is used, otherwise the type and identifier is used.
     */
    @Nullable
    AclObjectIdentity findObjectIdentity( AclObjectIdentity objectIdentity );

    /**
     * Find all the children of the given object identity.
     */
    List<AclObjectIdentity> findChildren( AclObjectIdentity parentIdentity );

    /**
     * Create a new object identity.
     */
    @CheckReturnValue
    AclObjectIdentity createObjectIdentity( AclObjectIdentity oid );

    /**
     * Update a given object identity so that it conforms to a given ACL object.
     */
    void updateObjectIdentity( AclObjectIdentity aclObjectIdentity, Acl acl );

    /**
     * Delete a given object identity.
     *
     * @param deleteChildren if true, the children are recursively deleted as well
     * @throws ChildrenExistException if deleteChildren is false and there are children associated to the object
     *                                identity, those must be removed beforehand
     */
    void deleteObjectIdentity( AclObjectIdentity objectIdentity, boolean deleteChildren ) throws ChildrenExistException;

    /**
     * Delete a given SID.
     */
    void deleteSid( AclSid sid );

    /**
     * Retrieve a SID conforming to the given object.
     * <p>
     * If the provided object as a non-null ID, it is used, otherwise either the principal or granted authority is used
     * depending on the type.
     */
    @Nullable
    AclSid findSid( AclSid sid );

    @CheckReturnValue
    AclSid findOrCreateSid( AclSid sid );
}
