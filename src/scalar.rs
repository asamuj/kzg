use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::mem;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From, Into};

use kzg::Fr as _;
use rust_kzg_blst::types::fr::FsFr;

/// Representation of a single BLS12-381 scalar value.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, From, Into, AsRef, AsMut, Deref, DerefMut)]
#[repr(transparent)]
pub struct Scalar(FsFr);

impl Hash for Scalar {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

impl PartialOrd<Self> for Scalar {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Scalar {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

#[cfg(feature = "serde")]
mod scalar_serde {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    // Custom wrapper so we don't have to write serialization/deserialization code manually
    #[derive(Serialize, Deserialize)]
    struct Scalar(#[serde(with = "hex::serde")] pub(super) [u8; super::Scalar::FULL_BYTES]);

    impl Serialize for super::Scalar {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Scalar(self.to_bytes()).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for super::Scalar {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let Scalar(bytes) = Scalar::deserialize(deserializer)?;
            Self::try_from(bytes).map_err(D::Error::custom)
        }
    }
}

impl From<&[u8; Self::SAFE_BYTES]> for Scalar {
    #[inline]
    fn from(value: &[u8; Self::SAFE_BYTES]) -> Self {
        let mut bytes = [0u8; Self::FULL_BYTES];
        bytes[..Self::SAFE_BYTES].copy_from_slice(value);
        Self::try_from(bytes).expect("Safe bytes always fit into scalar and thus succeed; qed")
    }
}

impl From<[u8; Self::SAFE_BYTES]> for Scalar {
    #[inline]
    fn from(value: [u8; Self::SAFE_BYTES]) -> Self {
        Self::from(&value)
    }
}

impl TryFrom<&[u8; Self::FULL_BYTES]> for Scalar {
    type Error = String;

    #[inline]
    fn try_from(value: &[u8; Self::FULL_BYTES]) -> Result<Self, Self::Error> {
        Self::try_from(*value)
    }
}

impl TryFrom<[u8; Self::FULL_BYTES]> for Scalar {
    type Error = String;

    #[inline]
    fn try_from(value: [u8; Self::FULL_BYTES]) -> Result<Self, Self::Error> {
        FsFr::from_bytes(&value).map(Scalar)
    }
}

impl From<&Scalar> for [u8; Scalar::FULL_BYTES] {
    #[inline]
    fn from(value: &Scalar) -> Self {
        value.0.to_bytes()
    }
}

impl From<Scalar> for [u8; Scalar::FULL_BYTES] {
    #[inline]
    fn from(value: Scalar) -> Self {
        Self::from(&value)
    }
}

impl Scalar {
    /// How many full bytes can be stored in BLS12-381 scalar (for instance before encoding). It is
    /// actually 254 bits, but bits are mut harder to work with and likely not worth it.
    ///
    /// NOTE: After encoding more bytes can be used, so don't rely on this as the max number of
    /// bytes stored within at all times!
    pub const SAFE_BYTES: usize = 31;
    /// How many bytes Scalar contains physically, use [`Self::SAFE_BYTES`] for the amount of data
    /// that you can put into it safely (for instance before encoding).
    pub const FULL_BYTES: usize = 32;

    /// Convert scalar into bytes
    pub fn to_bytes(&self) -> [u8; Scalar::FULL_BYTES] {
        self.into()
    }

    /// Convenient conversion from slice of scalar to underlying representation for efficiency
    /// purposes.
    #[inline]
    pub fn slice_to_repr(value: &[Self]) -> &[FsFr] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of underlying representation to scalar for efficiency
    /// purposes.
    #[inline]
    pub fn slice_from_repr(value: &[FsFr]) -> &[Self] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of optional scalar to underlying representation for efficiency
    /// purposes.
    pub fn slice_option_to_repr(value: &[Option<Self>]) -> &[Option<FsFr>] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of optional underlying representation to scalar for efficiency
    /// purposes.
    pub fn slice_option_from_repr(value: &[Option<FsFr>]) -> &[Option<Self>] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of scalar to underlying representation for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_to_repr(value: &mut [Self]) -> &mut [FsFr] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of underlying representation to scalar for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_from_repr(value: &mut [FsFr]) -> &mut [Self] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from optional mutable slice of scalar to underlying representation for
    /// efficiency purposes.
    pub fn slice_option_mut_to_repr(value: &mut [Option<Self>]) -> &mut [Option<FsFr>] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from optional mutable slice of underlying representation to scalar for
    /// efficiency purposes.
    pub fn slice_option_mut_from_repr(value: &mut [Option<FsFr>]) -> &mut [Option<Self>] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from vector of scalar to underlying representation for efficiency
    /// purposes.
    pub fn vec_to_repr(value: Vec<Self>) -> Vec<FsFr> {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory
        //  layout, original vector is not dropped
        unsafe {
            let mut value = mem::ManuallyDrop::new(value);
            Vec::from_raw_parts(
                value.as_mut_ptr() as *mut FsFr,
                value.len(),
                value.capacity(),
            )
        }
    }

    /// Convenient conversion from vector of underlying representation to scalar for efficiency
    /// purposes.
    pub fn vec_from_repr(value: Vec<FsFr>) -> Vec<Self> {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory
        //  layout, original vector is not dropped
        unsafe {
            let mut value = mem::ManuallyDrop::new(value);
            Vec::from_raw_parts(
                value.as_mut_ptr() as *mut Self,
                value.len(),
                value.capacity(),
            )
        }
    }

    /// Convenient conversion from vector of optional scalar to underlying representation for
    /// efficiency purposes.
    pub fn vec_option_to_repr(value: Vec<Option<Self>>) -> Vec<Option<FsFr>> {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory
        //  layout, original vector is not dropped
        unsafe {
            let mut value = mem::ManuallyDrop::new(value);
            Vec::from_raw_parts(
                value.as_mut_ptr() as *mut Option<FsFr>,
                value.len(),
                value.capacity(),
            )
        }
    }

    /// Convenient conversion from vector of optional underlying representation to scalar for
    /// efficiency purposes.
    pub fn vec_option_from_repr(value: Vec<Option<FsFr>>) -> Vec<Option<Self>> {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory
        //  layout, original vector is not dropped
        unsafe {
            let mut value = mem::ManuallyDrop::new(value);
            Vec::from_raw_parts(
                value.as_mut_ptr() as *mut Option<Self>,
                value.len(),
                value.capacity(),
            )
        }
    }
}
