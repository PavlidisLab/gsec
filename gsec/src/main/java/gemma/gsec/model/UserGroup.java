/*
 * The Gemma project.
 * 
 * Copyright (c) 2006-2012 University of British Columbia
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

package gemma.gsec.model;

import java.util.Collection;

/**
 * An organized group of researchers with an identifiable leader and group members.
 */
public abstract class UserGroup extends Describable implements SecuredNotChild {

    /**
     * Constructs new instances of {@link UserGroup}.
     */
    public static final class Factory {
        /**
         * Constructs a new instance of {@link UserGroup}.
         */
        public static UserGroup newInstance() {
            return new UserGroupImpl();
        }

    }

    /**
     * The serial version UID of this class. Needed for serialization.
     */
    private static final long serialVersionUID = 5795744069086222179L;
    private Collection<User> groupMembers = new java.util.HashSet<>();

    private Collection<GroupAuthority> authorities = new java.util.HashSet<GroupAuthority>();

    /**
     * No-arg constructor added to satisfy javabean contract
     * 
     * @author Paul
     */
    public UserGroup() {
    }

    /**
     * 
     */
    public Collection<GroupAuthority> getAuthorities() {
        return this.authorities;
    }

    /**
     * 
     */
    public Collection<User> getGroupMembers() {
        return this.groupMembers;
    }

    public void setAuthorities( Collection<GroupAuthority> authorities ) {
        this.authorities = authorities;
    }

    public void setGroupMembers( Collection<User> groupMembers ) {
        this.groupMembers = groupMembers;
    }

}