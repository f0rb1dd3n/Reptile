SECTIONS
{
	.data : {
		KHOOK_tbl = . ;
		*(.data.khook)
		KHOOK_tbl_end = . ;
	}
}
