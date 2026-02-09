import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 설정 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v35.13", layout="wide")

st.markdown("""
    <style>
    .version-header { font-size: 24px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 15px; border-radius: 8px; border-left: 8px solid #1565C0; margin-bottom: 15px; }
    .report-box { padding: 20px; border: 1px solid #ddd; background-color: #ffffff; border-radius: 8px; margin-bottom: 25px; }
    .item-box { padding: 10px 14px; margin-bottom: 8px; border-left: 4px solid #90CAF9; background-color: #F5F5F5; font-size: 15px; line-height: 1.6; }
    .highlight { background-color: #FFF59D; color: black; font-weight: bold; padding: 2px 4px; border-radius: 4px; }
    .meta-label { color: #1565C0; font-weight: bold; font-size: 16px; border-bottom: 2px solid #BBDEFB; margin-bottom: 10px; display: inline-block; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 및 초기화 함수 ---
DB_FILE = 'security_notes_archive.db'

def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
    conn.commit()
    conn.close()

# 앱 시작 시 DB 체크
init_db()

# --- 3. [통합 엔진] v35.13 (노이즈 필터링 강화) ---

def clean_cell_text(text):
    if not text: return ""
    return re.sub(r'\s+', ' ', str(text).replace('\n', ' ')).strip()

def repair_content(text):
    if not text: return ""
    # Apa * che, 펌웨 * 어 복구
    text = re.sub(r'([a-zA-Z])\s*[\*\-]\s*([a-zA-Z])', r'\1\2', text)
    text = re.sub(r'([가-힣])\s*[\*\-]\s*([가-힣])', r'\1\2', text)
    # 괄호 보정
    text = re.sub(r'\(\s+', '(', text)
    text = re.sub(r'\s+\)', ')', text)
    return text

def parse_pdf_v35(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        extracted_data = [] 
        
        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # --- 전략 수립 ---
            strategies = []
            
            # 1. [스마트 그리드] 헤더 좌표 탐색
            words = page.extract_words()
            header_map = {w['text']: w for w in words if w['text'] in ['유형', '기능분류', '요약']}
            
            if '기능분류' in header_map and '요약' in header_map:
                x1 = (header_map['유형']['x1'] + header_map['기능분류']['x0']) / 2 if '유형' in header_map else header_map['기능분류']['x0'] - 10
                x2 = (header_map['기능분류']['x1'] + header_map['요약']['x0']) / 2
                strategies.append({
                    "name": "smart",
                    "vertical_strategy": "explicit", "explicit_vertical_lines": [0, x1, x2, page.width],
                    "horizontal_strategy": "text", "intersection_y_tolerance": 10
                })
            
            # 2. [물리적 선]
            strategies.append({"name": "lines", "vertical_strategy": "lines", "horizontal_strategy": "lines"})
            
            # 3. [강제 하드코딩] A4 가로폭(약 600) 기준 대략적인 3단 분할
            #    유형(좁음) | 분류(중간) | 요약(넓음)
            strategies.append({
                "name": "hardcoded",
                "vertical_strategy": "explicit", "explicit_vertical_lines": [0, 50, 150, page.width],
                "horizontal_strategy": "text", "intersection_y_tolerance": 10
            })
            
            page_extracted = False
            
            for settings in strategies:
                if page_extracted: break
                try:
                    tables = page.extract_tables(table_settings=settings)
                except: continue

                if not tables: continue
                
                temp_data = []
                for table in tables:
                    for row in table:
                        cells = [clean_cell_text(c) for c in row]
                        if not cells: continue
                        
                        v_type = v_cat = v_desc = v_id = ""
                        
                        # 컬럼 매핑 (유연하게)
                        if len(cells) >= 3:
                            v_type, v_cat, v_desc = cells[0], cells[1], cells[2]
                            v_id = cells[3] if len(cells) > 3 else ""
                        elif len(cells) == 2: # 텍스트 모드 등에서 2개만 잡힐 때
                             v_type, v_desc = cells[0], cells[1]

                        # [필터링 1] 헤더 행 스킵
                        if "유형" in v_type and "분류" in v_cat: continue

                        # [필터링 2] 불필요한 링크/메타데이터 스킵 (여기가 핵심)
                        if any(x in v_type for x in ["[릴리즈노트]", "문서", "제약사항", "다운로드", "제품명"]): continue
                        if "Last Updated" in v_desc or "Build" in v_desc: continue
                        if not v_desc or len(v_desc) < 5: continue # 너무 짧은 내용 버림

                        # 키워드 검사 (기호 포함)
                        keywords = ['개선', '신규', '이슈', '수정', 'BUG', '+', '↑', 'System', 'SSL', 'VPN', 'Network']
                        
                        is_valid = False
                        # 내용이나 분류에 키워드가 있어야 함
                        if any(k in v_type for k in keywords) or any(k in v_cat for k in keywords) or any(k in v_desc for k in keywords):
                            is_valid = True
                        
                        if is_valid:
                            # 1. 정제
                            clean_desc = re.sub(r'^[•\-o]\s*', '', v_desc)
                            clean_desc = repair_content(clean_desc)
                            
                            # 2. Type/Cat 분리
                            # SystemApa -> System Apache
                            final_cat = re.sub(r'(System)([A-Z])', r'\1 \2', v_cat)
                            final_cat = re.sub(r'(SSL\s*VPN)([가-힣a-zA-Z])', r'\1 \2', final_cat)

                            # 3. Type 아이콘 치환
                            final_type = v_type.replace('↑', '개선').replace('+', '신규')
                            
                            cat_part = f" {final_cat}" if final_cat and final_cat != final_type else ""
                            id_part = f" ({v_id})" if v_id and v_id not in ["-", ""] else ""
                            
                            line_str = f"[{final_type}]{cat_part} * {clean_desc}{id_part}"
                            
                            if line_str not in temp_data:
                                temp_data.append(line_str)
                
                # 데이터가 3건 이상 나오면 성공으로 간주
                if len(temp_data) >= 3:
                    extracted_data.extend(temp_data)
                    page_extracted = True
            
        # 중복 제거
        extracted_data = list(dict.fromkeys(extracted_data))

        # 메타데이터
        v = re.search(r'TrusGuard\s+v?([0-9\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        
        ssl_match = re.search(r'OpenSSL.*?(?:->\s*|\s)([\d\.]+[a-z]?)', full_raw, re.I)
        openssl = ssl_match.group(1) if ssl_match else "-"
        
        ssh_match = re.search(r'OpenSSH.*?([\d\.]+p\d+)', full_raw, re.I)
        openssh = ssh_match.group(1) if ssh_match else "-"

    return {
        "version": version,
        "openssl": openssl,
        "openssh": openssh,
        "content": "\n\n".join(extracted_data),
        "raw": full_raw
    }

# --- 4. 사이드바 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v35"

conn = get_connection()
cursor = conn.cursor()

with st.sidebar:
    st.header("📜 버전 히스토리")
    try:
        hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    except:
        hist_df = pd.DataFrame()

    sel_v = st.radio("버전 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 등록", expanded=True):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            if uploaded:
                for f in uploaded:
                    try:
                        info = parse_pdf_v35(f)
                        cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                        if not cursor.fetchone():
                            cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                        (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                            conn.commit()
                            st.success(f"v{info['version']} 저장됨")
                        else:
                            st.warning(f"v{info['version']} 이미 존재")
                    except Exception as e:
                        st.error(f"오류: {e}")
                st.rerun()

    # [NEW] DB 완전 초기화 메뉴
    st.divider()
    with st.expander("💀 관리자 메뉴 (위험)"):
        if st.button("💣 DB 완전 초기화 (복구 불가)", type="primary"):
            cursor.execute("DROP TABLE IF EXISTS notes")
            conn.commit()
            init_db() # 테이블 재생성
            st.toast("DB가 초기화되었습니다.")
            st.rerun()

        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전", hist_df['version'].tolist())
            if st.button("🚨 선택 버전 삭제"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

# --- 5. 메인 렌더링 ---
st.title("🛡️ TrusGuard 통합 관제 (v35.13)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def render_report_card(version, openssl, openssh, content, search_kws=None):
    st.markdown(f"<div class='version-header'>📦 TrusGuard {version}</div>", unsafe_allow_html=True)
    with st.container():
        st.markdown("<div class='report-box'>", unsafe_allow_html=True)
        st.markdown(f"<div class='meta-label'>🔒 보안 컴포넌트</div>", unsafe_allow_html=True)
        st.text(f"OpenSSL: {openssl} / OpenSSH: {openssh}")
        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown(f"<div class='meta-label'>📋 상세 변경 내역</div>", unsafe_allow_html=True)
        if content:
            paras = content.split('\n\n')
            has_content = False
            for p in paras:
                if not p.strip(): continue
                display_text = p.strip()
                if search_kws:
                    if not all(k.lower() in display_text.lower() for k in search_kws): continue
                    for k in search_kws:
                        display_text = re.sub(f"({re.escape(k)})", r"<span class='highlight'>\1</span>", display_text, flags=re.I)
                st.markdown(f"<div class='item-box'>{display_text}</div>", unsafe_allow_html=True)
                has_content = True
            
            if not has_content and search_kws:
                st.info("검색 결과가 없습니다.")
        else:
            st.warning("데이터 추출 실패")
        st.markdown("</div>", unsafe_allow_html=True)

if keyword:
    kws = keyword.split()
    query = "SELECT * FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    if res.empty: st.info("검색 결과 없음")
    else:
        for _, row in res.iterrows(): render_report_card(row['version'], row['openssl'], row['openssh'], row['improvements'], kws)
elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    render_report_card(r['version'], r['openssl'], r['openssh'], r['improvements'])
else:
    st.info("좌측 사이드바에서 PDF 파일을 등록하거나 버전을 선택해주세요.")
