/*
 * The Gemma project.
 * 
 * Copyright (c) 2006 University of British Columbia
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

/**
 * @see ubic.gemma.model.common.auditAndSecurity.User
 */
public class UserImpl extends User {

    private Long id;

    /**
     * The serial version UID of this class. Needed for serialization.
     */
    private static final long serialVersionUID = -4115557703404682086L;

    @Override
    public Long getId() {
        // TODO Auto-generated method stub
        return this.id;
    }

    public void setId( Long id ) {
        this.id = id;
    }
}