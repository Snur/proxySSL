function afficher(com) {
	var comment = document.getElementById("comment");
	comment.disabled = com.checked ? false : true;
	if (!comment.disabled) {
		comment.focus();
	}
}
