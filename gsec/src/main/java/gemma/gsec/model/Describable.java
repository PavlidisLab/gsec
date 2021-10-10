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

/**
 *
 */
public interface Describable extends java.io.Serializable {
    /**
     * A human-readable description of the object
     */
    String getDescription();

    /**
     *
     */
    Long getId();

    /**
     * The name of an object is a possibly ambiguous human-readable identifier that need not be an external database
     * reference.
     */
    String getName();

    void setDescription( String description );

    void setId( Long id );

    void setName( String name );

}