/*
 * The Gemma project
 *
 * Copyright (c) 2013 University of British Columbia
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

import java.io.Serializable;

/**
 * Indicates that a value object represents a Securable so security filtering can be provided during reading.
 *
 * @author cmcdonald
 * @version $Id: SecureValueObject.java,v 1.5 2013/09/14 16:55:17 paul Exp $
 */
public interface SecureValueObject extends Serializable, Securable {

    /**
     * @return true if the object is public
     */
    boolean getIsPublic();

    /**
     * @return
     */
    boolean getIsShared();

    /**
     * @return the securable Class of the represented entity.
     */
    Class<? extends Securable> getSecurableClass();

    /**
     * @return
     */
    boolean getUserCanWrite();

    /**
     * @return true if the object is owned by the current user
     */
    boolean getUserOwned();

    void setIsPublic( boolean isPublic );

    /**
     * @param isShared
     */
    void setIsShared( boolean isShared );

    /**
     * @param userCanWrite
     */
    void setUserCanWrite( boolean userCanWrite );

    /**
     * @param isUserOwned
     */
    void setUserOwned( boolean isUserOwned );

}
