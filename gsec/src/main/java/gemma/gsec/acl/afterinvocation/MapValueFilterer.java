/*
 * The Gemma project
 *
 * Copyright (c) 2010 University of British Columbia
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

import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * @author paul
 * @version $Id: MapValueFilterer.java,v 1.2 2012/05/27 02:58:03 paul Exp $
 * @param <T> the type of value (Object is fine)
 */
public class MapValueFilterer<T> implements Filterer<T> {

    protected static final Log logger = LogFactory.getLog( MapFilterer.class );

    private Map<?, T> map;

    // collectionIter offers significant performance optimisations (as
    // per acegisecurity-developer mailing list conversation 19/5/05)
    private Iterator<T> collectionIter;
    private Set<T> removeList;

    MapValueFilterer( Map<?, T> map ) {
        this.map = map;

        // We create a Set of objects to be removed from the Map,
        // as ConcurrentModificationException prevents removal during
        // iteration, and making a new Collection to be returned is
        // problematic as the original Collection implementation passed
        // to the method may not necessarily be re-constructable (as
        // the Collection(collection) constructor is not guaranteed and
        // manually adding may lose sort order or other capabilities)
        removeList = new HashSet<>();
    }

    /**
     * @see org.acegisecurity.afterinvocation.Filterer#getFilteredObject()
     */
    @Override
    public Object getFilteredObject() {
        // Now the Iterator has ended, remove Objects from Collection
        Iterator<T> removeIter = removeList.iterator();

        int originalSize = map.size();

        while ( removeIter.hasNext() ) {
            map.remove( removeIter.next() );
        }

        if ( logger.isDebugEnabled() ) {
            logger.debug( "Original map contained " + originalSize + " elements; now contains " + map.size()
                    + " elements" );
        }

        return map;
    }

    /**
     * @see org.acegisecurity.afterinvocation.Filterer#iterator()
     */
    @Override
    public Iterator<T> iterator() {
        collectionIter = map.values().iterator();

        return collectionIter;
    }

    /**
     * @see org.acegisecurity.afterinvocation.Filterer#markAsMissing(java.lang.Object)
     */
    @Override
    public void remove( T object ) {
        collectionIter.remove();
    }
}
