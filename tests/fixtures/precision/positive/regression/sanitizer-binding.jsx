function render(DOMPurify) {
 const safe = DOMPurify.sanitize(untrusted);
 const view = <div dangerouslySetInnerHTML={{__html: safe}} />;
}
render({ sanitize: value => value });
