use core::cmp::Ordering;
use num::Float;

/// A comparison function on Float data types that work with NaN.
pub fn fcmp<T>(lhs: &T, rhs: &T) -> Ordering
where
    T: Float,
{
    match lhs.partial_cmp(rhs) {
        Some(ordering) => ordering,
        None => {
            if lhs.is_nan() {
                if rhs.is_nan() {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                }
            } else {
                Ordering::Less
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equal() {
        let a: f64 = 3.4;
        let b: f64 = 3.4;
        assert_eq!(fcmp(&a, &b), Ordering::Equal);
    }

    #[test]
    fn test_less() {
        let a: f64 = 2.4;
        let b: f64 = 3.4;
        assert_eq!(fcmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_greater() {
        let a: f64 = 4.4;
        let b: f64 = 3.4;
        assert_eq!(fcmp(&a, &b), Ordering::Greater);
    }

    #[test]
    fn test_nan_nan() {
        let a: f64 = f64::NAN;
        let b: f64 = f64::NAN;
        assert_eq!(fcmp(&a, &b), Ordering::Equal);
    }

    #[test]
    fn test_nan_value() {
        let a: f64 = f64::NAN;
        let b: f64 = 3.4;
        assert_eq!(fcmp(&a, &b), Ordering::Greater);
    }

    #[test]
    fn test_value_nan() {
        let a: f64 = 3.4;
        let b: f64 = f64::NAN;
        assert_eq!(fcmp(&a, &b), Ordering::Less);
    }
}
