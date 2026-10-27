render_template_string(
    """
    {{ request.args.foo }}
    {{ config.DEBUG }}
    """
)
