SECTIONS
{
	.data : {
		__khook_tbl = . ;
		*(.data.khook)
		__khook_tbl_end = . ;
	}
}
