/**
 * Pairs/Tupple Abstract Data Type
 * @author benjamin
 *
 * @param <T1> Type 1
 * @param <T2> Type 2
 */
public class Pair<T1,T2> {
	T1 _i;
	T2 _j;
	public Pair(T1 i, T2 j){
		_i = i;
		_j = j;
	}
	public T1 getVal1() {
		return _i;
	}
	public void setVal1(T1 _i) {
		this._i = _i;
	}
	public T2 getVal2() {
		return _j;
	}
	public void setVal2(T2 _j) {
		this._j = _j;
	}
}
