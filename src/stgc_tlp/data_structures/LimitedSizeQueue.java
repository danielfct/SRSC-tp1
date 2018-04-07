package stgc_tlp.data_structures;

import java.util.ArrayList;

public class LimitedSizeQueue<E> extends ArrayList<E> {

	private static final long serialVersionUID = -2768525003632808489L;
	
	private int maxSize;

    public LimitedSizeQueue(int size){
        this.maxSize = size;
    }

    public boolean add(E e){
        boolean r = super.add(e);
        if (size() > maxSize){
            removeRange(0, size() - maxSize);
        }
        return r;
    }

    public E getYongest() {
        return get(size() - 1);
    }

    public E getOldest() {
        return get(0);
    }
}