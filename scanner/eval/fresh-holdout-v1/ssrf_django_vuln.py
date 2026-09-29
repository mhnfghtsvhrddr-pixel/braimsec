import requests

def webhook(request):
    target = request.GET.get("target")
    r = requests.post(target, json={"ping": 1})
    return r.text
