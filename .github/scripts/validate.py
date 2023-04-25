import requests
import json
import sys
from http.cookies import SimpleCookie
import time
import os

stacks = json.loads(os.environ['HACKERRANK_STACKS'])

session = requests.session()

base_url = "https://www.hackerrank.com/"

headers = {
    'authority': 'www.hackerrank.com',
    'accept': '*/*',
    'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
    'cache-control': 'no-cache',
    'content-type': 'application/json',
    'cookie': '_gd_visitor=10acf504-c971-42dd-88eb-dfb0a6147d8f; _gd_svisitor=16312b179452000023eed26140010000a6182600; _wchtbl_uid=0a219a13-6796-4919-a6c9-e2908817a17d; _ga=GA1.1.1534939918.1641211862; _uetvid=f975b3406c9111ecbca9f9440ed6dbdd; _mkto_trk=id:487-WAY-049&token:_mch--1641548726604-53441; hackerrank_mixpanel_token=f0c345f1-f42a-45df-8702-f899c8ed3eb8; _fbp=fb.1.1643290428227.68922230; optimizelyEndUserId=oeu1643290467943r0.5880077639759551; optimizelySegments=%7B%221709580323%22%3A%22false%22%2C%221717251348%22%3A%22gc%22%2C%221719390155%22%3A%22search%22%2C%222308790558%22%3A%22none%22%7D; optimizelyBuckets=%7B%7D; _biz_uid=af58eb20e82a4215ada7e163b2ee8242; _mkto_trk=id:487-WAY-049&token:_mch--1641548726604-53441; cp_user_settings={%22theme%22:%22dark%22}; enableIntellisenseUserPref=true; userty.core.p.6bd7b3=__2VySWQiOiI1NzQxOGE2ZDI3OTY0ZjdmNTAwZTk5MmE0ODNiMDMyZCIsIml2IjoiNjMxMjE2In0=eyJ1c; _clck=jqfhks|1|f5p|0; userty.core.p.1be7b4=__2VySWQiOiI0MDUxMGQzOTc0ZTZkMmY2YjA2ODBkZTFhMzhjM2M0NCJ9eyJ1c; __utmz=74197771.1672937969.5.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); __stripe_mid=e34566ca-70d6-42c3-afb6-5b8e84f231eb6e5a64; show_cookie_banner=false; drift_aid=7b54bc97-8bb0-46ad-b29e-5962c1d994b3; driftt_aid=7b54bc97-8bb0-46ad-b29e-5962c1d994b3; _ga_871V12MEY1=GS1.1.1677037272.1.1.1677037310.0.0.0; referrer=direct; _pk_id.5.fe0a=fb279bd4fc494bef.1678255047.; h_r=hrw; h_l=domains; h_v=_default; _pk_ref.5.fe0a=%5B%22hrwCandidateFeedback%22%2C%22%22%2C1679629053%2C%22https%3A%2F%2Fpreview.hackerrank.com%2F%22%5D; hrx_candidate=eyJfcmFpbHMiOnsibWVzc2FnZSI6IkJBaEpJbk43SW5SbGMzUmZhR0Z6YUNJNklqSnlkR0ZuY1RNM2NXY3dJaXdpWlcxaGFXd2lPaUpwYzIxbFpYUXViV0ZyYTJGeUsyUmxka0JvWVdOclpYSnlZVzVyTG1OdmJTSXNJbU55WldGMFpXUmZZWFFpT2lJeU1ESXpMVEF6TFRJMFZERXdPalV3T2pFeUxqRTFNbG9pZlFZNkJrVlUiLCJleHAiOiIyMDI1LTAzLTI0VDEwOjUwOjEyLjE1MloiLCJwdXIiOm51bGx9fQ%3D%3D--c74c6bc54c5981956ac050d7376354aea801a027; hacker_editor_theme=light; _gid=GA1.2.1091321570.1681711167; _gid=GA1.1.1091321570.1681711167; _uetsid=0299cc80dce511ed848ea9ea22a78335; _gcl_au=1.1.1063728444.1681729752; __utma=74197771.1534939918.1641211862.1681115442.1681731460.11; _biz_flagsA=%7B%22Version%22%3A1%2C%22ViewThrough%22%3A%221%22%2C%22XDomain%22%3A%221%22%2C%22Frm%22%3A%221%22%2C%22Mkto%22%3A%221%22%7D; fileDownload=true; session_referrer=https%3A%2F%2Fhackerrank.okta.com%2F; session_referring_domain=hackerrank.okta.com; _hrank_session=d8f7337edc64777a2a4edeb2d016d0f5487a5579e0d1146704e26989f9a59530ff10119205faa58cc8b397c4db9a848d5a852fd389022b788ba6ec4fbb086a27; user_type=recruiter; _biz_nA=407; _biz_pendingA=%5B%5D; session_landing_url=https%3A%2F%2Fwww.hackerrank.com%2Fwork%2Fprefetch_data%3Fcopyscrape%3Dtrue%26show_tags%3Dtrue%26first_run_feature_ids%3D35%252C16%252C17%252C19%252C24%252C26%252C28%252C20%252C21%252C22%252C23%252C29%252C30%252C31%252C32%252C33%252C34%26get_feature_feedback_list%3Dtrue; web_browser_id=fa5a5a054dd84528f8a9ca8db63c5ae5; homepage_variant=about:srcdoc; _wchtbl_sid=7ed422a9-0912-4008-931f-67d0bd513ea7; _an_uid=-1; hackerrankx_mixpanel_token=83c1241e-fca5-4ca1-8c8a-54244be9bbe5; cebs=1; _ce.s=v~74b62003546818871fb537e5b528bf592bbb4406~vpv~14~ir~1~gtrk.la~leegeqnh~v11.rlc~1681711168261; ln_or=eyI0Nzc3MCI6ImQiLCI1ODIxMSI6ImQifQ%3D%3D; _ce.clock_event=1; _gd_session=6360aded-75a9-4225-8691-b287d10b86d4; _hp2_ses_props.547804831=%7B%22ts%22%3A1681815761442%2C%22d%22%3A%22www.hackerrank.com%22%2C%22h%22%3A%22%2F%22%7D; _ce.clock_data=-25%2C49.37.215.39%2C1; mp_bcb75af88bccc92724ac5fd79271e1ff_mixpanel=%7B%22distinct_id%22%3A%20%22f0c345f1-f42a-45df-8702-f899c8ed3eb8%22%2C%22%24device_id%22%3A%20%2217e1ff2388c65e-022621397508a1-1e396452-1d73c0-17e1ff2388eb33%22%2C%22%24user_id%22%3A%20%22f0c345f1-f42a-45df-8702-f899c8ed3eb8%22%2C%22%24initial_referrer%22%3A%20%22%24direct%22%2C%22%24initial_referring_domain%22%3A%20%22%24direct%22%2C%22%24search_engine%22%3A%20%22google%22%7D; cebsp_=3; _ga=GA1.2.1534939918.1641211862; _ga_R0S46VQSNQ=GS1.1.1681815761.10.1.1681815768.0.0.0; _ga_BCP376TP8D=GS1.1.1681815761.15.1.1681815768.0.0.0; _ga_X2HP4BPSD7=GS1.1.1681815761.10.1.1681815768.0.0.0; _ga_0QME21KCCM=GS1.1.1681815761.10.1.1681815768.0.0.0; _ga_4G810X81GK=GS1.1.1681815761.10.1.1681815768.0.0.0; _ga_ZDWKWB1ZWT=GS1.1.1681815761.10.1.1681815768.0.0.0; _gat_UA-45092266-19=1; mp_bcb75af88bccc92724ac5fd79271e1ff_mixpanel=%7B%22distinct_id%22%3A%20%22f0c345f1-f42a-45df-8702-f899c8ed3eb8%22%2C%22%24device_id%22%3A%20%2217e1ff2388c65e-022621397508a1-1e396452-1d73c0-17e1ff2388eb33%22%2C%22%24user_id%22%3A%20%22f0c345f1-f42a-45df-8702-f899c8ed3eb8%22%2C%22%24initial_referrer%22%3A%20%22%24direct%22%2C%22%24initial_referring_domain%22%3A%20%22%24direct%22%2C%22%24search_engine%22%3A%20%22google%22%7D; _hp2_id.547804831=%7B%22userId%22%3A%221338954506357635%22%2C%22pageviewId%22%3A%222638179860811544%22%2C%22sessionId%22%3A%228099003474021271%22%2C%22identity%22%3Anull%2C%22trackerVersion%22%3A%224.0%22%7D; fs_uid=#Q02VK#4805812821938176:4505680524070912:1681394770961::1#c45f6355#/1711191012; access_token=5f08947d2107d563795c8dfd2e5e2414a5c9953872ed6df236c5e613753c73ae',
    'newrelic': 'eyJ2IjpbMCwxXSwiZCI6eyJ0eSI6IkJyb3dzZXIiLCJhYyI6IjMxMTA1NjMiLCJhcCI6IjE3MDczNTc0MjAiLCJpZCI6IjRjMmQ4YTA5MDEwNTkyYWMiLCJ0ciI6IjJlYTI1OTI0M2Q2NTVjZTAxYTQxZjhiMGIxY2NjY2EwIiwidGkiOjE2ODE4MTU4MjM0MDJ9fQ==',
    'origin': 'https://www.hackerrank.com',
    'pragma': 'no-cache',
    'referer': 'https://www.hackerrank.com/work/login',
    'sec-ch-ua': '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'traceparent': '00-2ea259243d655ce01a41f8b0b1cccca0-4c2d8a09010592ac-01',
    'tracestate': '3110563@nr=0-1-3110563-1707357420-4c2d8a09010592ac----1681815823402',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'x-csrf-token': 'pWzFKzrg81GZssGJr1f+QD/fB+2uRrE5z7N1Ks43WhCN/oU3Pm/QFL7pO3M1FOtpfzAiTwsgOGJUv97B85iOhg==',
    'x-newrelic-id': 'VwcGUVNVCxABUldbDgMBX1AJ'
}


def set_headers():
    cookie = SimpleCookie()
    cookie.load(headers['cookie'])
    cookies = {}
    cookieStr = ''
    # Parse original cookies
    for key, morsel in cookie.items():
        cookies[key] = morsel.value
    # Update new values from session
    for c in session.cookies:
        cookies[c.name] = c.value
    # Construct cookie string
    for k, v in cookies.items():
        cookieStr += f"{k}={v};"
    headers['cookie'] = cookieStr


def login():
    print('logging into hackerrank....')
    auth_url = base_url + "work/login_user"

    payload = json.dumps({
        "email": os.environ['HACKERRANK_EMAIL'],
        "password": os.environ['HACKERRANK_PASSWORD'],
        "target": None,
        "fingerprint": "972b61c6a7ba223b1b221921ff9c8a0f",
        "remember_me": "false",
        "logout_all_sessions": True
    })

    response = session.request("POST", auth_url, headers=headers, data=payload)
    if response.status_code != 200:
        raise Exception("Failed to login")


def question_exists(qid):
    print('finding question in company library...')

    library_url = base_url + \
        f"x/api/v1/library?limit=1&library=personal_all&tags={qid}"
    response = session.request("GET", library_url)

    if response.status_code != 200:
        raise Exception("Failed to find question")

    data = response.json()

    if len(data['model']['questions']) != 0:
        return True, data['model']['questions'][0]

    return False, {}


def clone_question(qid):
    print('cloning question...')

    clone_url = base_url + "x/api/v1/questions/clone"
    payload = json.dumps({
        "id": qid,
        "name": f"Copy of {qid}"
    })
    response = session.request(
        "POST", clone_url, data=payload, headers=headers)

    if response.status_code != 200:
        raise Exception("Failed to clone question")

    data = response.json()

    return data['question']


def tag_question(question, qid):
    print("tagging question...")
    update_url = base_url + f"x/api/v1/questions/{question['id']}"
    question['visible_tags_array'].append(f"{qid}")
    payload = json.dumps({
        "visible_tags_array": question['visible_tags_array'],
        "sub_type": stacks.get(question["sub_type"], default=question["sub_type"])
    })
    response = session.request(
        "PUT", update_url, data=payload, headers=headers)

    if response.status_code != 200:
        raise Exception("Failed to tag question")


def update_project_zip(question):
    print('updating project zip...')
    update_url = base_url + f"x/api/v1/questions/{question['id']}/upload"
    files = [
        ('source_file', ('project.zip', open('project.zip', 'rb'), 'application/zip'))
    ]
    del headers['content-type']
    response = session.post(update_url, headers=headers,
                            files=files, data={'a': 1})

    if response.status_code != 200:
        print(response.status_code)
        raise Exception("Failed to update project zip")


def validate_question(question):
    print('validating question...')
    validate_url = base_url + \
        f"x/api/v1/questions/{question['id']}/validate_fullstack"
    headers['content-type'] = 'application/json'

    response = requests.request("POST", validate_url, headers=headers)

    if response.status_code != 200:
        raise Exception("Failed to start validation...")

    return response.json()['task_id']


def check_validation_status(task_id):
    print('polling on validation task with id', task_id)
    poll_url = base_url + f"x/api/v1/delayed_tasks/{task_id}/poll"

    while True:
        time.sleep(5)
        response = session.get(poll_url)

        if response.status_code != 200:
            raise Exception("Failed to get validation status")

        data = response.json()
        if data['status_code'] == 2 or data['response']['additional_data']['valid'] == True:
            print(data)
            return data


def process_validator_response(validator_response):
    print('processing validator response...')
    validation_success = validator_response['valid'] == True
    if not validation_success:
        for _, v in validator_response['data'].items():
            if v['valid'] != True:
                print(v)
                raise Exception(v['message'])
    print('validation success..')


def main():
    login()
    set_headers()
    # id of original question from library
    qid = sys.argv[1].split('-')[0]
    print(f"supplied qid is {qid}")
    # id of clone of question
    exists, question = question_exists(qid)

    if not exists:
        question = clone_question(qid)
    print('question copy has id', question['id'])
    tag_question(question, qid)
    update_project_zip(question)
    task_id = validate_question(question)
    validator_response = check_validation_status(task_id)
    process_validator_response(validator_response['response'])


if __name__ == "__main__":
    main()
